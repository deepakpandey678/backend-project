"""API routes  (all under /api/v1)."""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import date, timedelta
from typing import Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from core import (
    CurrentUser,
    audit,
    client_ip,
    csrf_for,
    current_user,
    get_db,
    issue_token,
    pwd,
    require_role,
    settings,
    vault_decrypt,
    vault_encrypt,
)
from excel_export import build_workbook
from timecalc import day_to_json, fetch_daily_rows, split_hms, summarize

router = APIRouter(prefix="/api/v1")


def err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, {"code": code, "message": message})


# ======================================================================
# AUTH
# ======================================================================
class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


@router.post("/auth/login")
async def login(
    body: LoginBody,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = client_ip(request)
    row = (
        await db.execute(
            text(
                """SELECT id, full_name, role, password_hash, is_active, failed_logins, locked_until,
                                           (locked_until IS NOT NULL AND locked_until > CURRENT_TIMESTAMP) AS locked
                                    FROM employees WHERE email = :e"""
            ),
            {"e": body.email},
        )
    ).first()
    generic = err(401, "BAD_CREDENTIALS", "Email or password is incorrect.")
    if not row or not row.is_active:
        pwd.hash("timing-equaliser")  # keep timing similar for unknown users
        raise generic
    if row.locked:
        raise err(429, "LOCKED", "Too many attempts. Try again in a few minutes.")
    if not pwd.verify(body.password, row.password_hash):
        await db.execute(
            text("""
                    UPDATE employees 
                    SET failed_logins = failed_logins + 1,
                        locked_until = CASE WHEN failed_logins + 1 >= 5 
                                            THEN DATETIME('now', '+15 minutes') END
                    WHERE id = :i
                """),
            {"i": row.id},
        )
        await audit(db, row.id, "LOGIN_FAILED", ip=ip)
        await db.commit()
        raise generic

    await db.execute(
        text(
            "UPDATE employees SET failed_logins = 0, locked_until = NULL WHERE id = :i"
        ),
        {"i": row.id},
    )
    token, jti = issue_token(row.id, row.role)
    common = dict(
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.access_ttl_minutes * 60,
        path="/",
    )
    response.set_cookie("access_token", token, httponly=True, **common)
    response.set_cookie(
        "csrf_token", csrf_for(str(row.id), jti), httponly=False, **common
    )
    await audit(db, row.id, "LOGIN", ip=ip)
    return {
        "id": str(row.id),
        "name": row.full_name,
        "role": row.role,
        "access_token": token,
    }


@router.post("/auth/logout")
async def logout(
    response: Response,
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("csrf_token", path="/")
    await audit(db, user.id, "LOGOUT", ip=user.ip)
    return {"ok": True}


@router.get("/me")
async def me(
    user: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    r = (
        await db.execute(
            text(
                """SELECT e.id, e.emp_code, e.full_name, e.email, e.role, s.name AS shift_name, o.name AS office_name
                                  FROM employees e JOIN shifts s ON s.id = e.shift_id JOIN offices o ON o.id = e.office_id
                                  WHERE e.id = :i"""
            ),
            {"i": user.id},
        )
    ).one()
    return {
        "id": str(r.id),
        "emp_code": r.emp_code,
        "name": r.full_name,
        "email": r.email,
        "role": r.role,
        "shift": r.shift_name,
        "office": r.office_name,
    }


# ======================================================================
# PUNCH
# ======================================================================
@router.get("/punch/challenge")
async def punch_challenge(
    user: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    """Single-use token. The liveness capture must be taken after this call and sent with the punch."""
    r = (
        await db.execute(
            text(
                """INSERT INTO punch_challenges (employee_id, expires_at)
                                  VALUES (:e, now() + make_interval(secs => :ttl)) RETURNING id"""
            ),
            {"e": user.id, "ttl": settings.challenge_ttl_seconds},
        )
    ).one()
    return {"challenge": str(r.id), "expires_in": settings.challenge_ttl_seconds}


async def verify_liveness(photo: bytes, challenge: str) -> float:
    """PLUG-IN POINT. Call a real server-side liveness / face-match provider here
    (e.g. AWS Rekognition Face Liveness, Azure Face Liveness, FaceTec, Onfido) and
    return a 0..1 score. The browser can be modified by the user, so the pass/fail
    decision must never come from client code.

    This development stub only checks that the upload is a JPEG and returns 0.90."""
    if not photo.startswith(b"\xff\xd8\xff"):
        return 0.0
    return 0.90


def store_photo(employee_id: UUID, kind: str, data: bytes) -> str:
    """Replace with S3/GCS (SSE-KMS, private bucket, short-lived signed URLs)."""
    os.makedirs(settings.photo_dir, exist_ok=True)
    key = f"{employee_id}_{kind}_{secrets.token_hex(8)}.jpg"
    with open(os.path.join(settings.photo_dir, key), "wb") as fh:
        fh.write(data)
    return key


async def _reject(
    db: AsyncSession,
    user: CurrentUser,
    kind: str,
    code: str,
    message: str,
    *,
    lat: float | None = None,
    lng: float | None = None,
    acc: float | None = None,
    dist: float | None = None,
    device: str | None = None,
    status: int = 422,
):
    await db.execute(
        text(
            """INSERT INTO punch_attempts (employee_id, kind, accepted, reason_code, location, accuracy_m,
                                                         distance_m, device_id, ip)
                             VALUES (:e, CAST(:k AS punch_kind), false, :c,
                                     CASE WHEN CAST(:lng AS float8) IS NULL THEN NULL
                                          ELSE ST_SetSRID(ST_MakePoint(CAST(:lng AS float8), CAST(:lat AS float8)), 4326)::geography END,
                                     :a, :d, :dev, CAST(:ip AS inet))"""
        ),
        {
            "e": user.id,
            "k": kind,
            "c": code,
            "lat": lat,
            "lng": lng,
            "a": acc,
            "d": dist,
            "dev": device,
            "ip": user.ip,
        },
    )
    await db.commit()  # persist the attempt even though we raise
    raise err(status, code, message)


async def _punch(
    kind: Literal["IN", "OUT"],
    user: CurrentUser,
    db: AsyncSession,
    *,
    lat: float,
    lng: float,
    accuracy_m: float,
    is_mock: bool,
    device_id: str,
    challenge: UUID,
    photo: UploadFile,
) -> dict:
    ctx = dict(lat=lat, lng=lng, acc=accuracy_m, device=device_id)

    # 1. Challenge: atomic single use (blocks replayed captures)
    ok = (
        await db.execute(
            text("""UPDATE punch_challenges SET consumed_at = now()
                                   WHERE id = :c AND employee_id = :e AND consumed_at IS NULL AND expires_at > now()
                                   RETURNING id"""),
            {"c": challenge, "e": user.id},
        )
    ).first()
    if not ok:
        await _reject(
            db,
            user,
            kind,
            "CHALLENGE_INVALID",
            "This verification has expired. Start again.",
            **ctx,
        )

    # 2. Mock-location flag (only reliable from a native shell that reads isFromMockProvider)
    if is_mock:
        await _reject(
            db,
            user,
            kind,
            "MOCK_LOCATION",
            "Mock location is turned on. Turn it off and try again.",
            **ctx,
            status=403,
        )

    # 3. GPS quality
    if accuracy_m > settings.max_accuracy_m:
        await _reject(
            db,
            user,
            kind,
            "LOW_ACCURACY",
            f"GPS signal is weak (±{accuracy_m:.0f} m). Move to an open area and retry.",
            **ctx,
        )

    # 4. Geofence (PostGIS, geography = metres on the spheroid)
    g = (
        await db.execute(
            text(
                """SELECT o.name, o.radius_m,
                                         ST_Distance(o.location, ST_SetSRID(ST_MakePoint(:lng, :lat), 4326)::geography) AS dist
                                  FROM employees e JOIN offices o ON o.id = e.office_id WHERE e.id = :e"""
            ),
            {"e": user.id, "lat": lat, "lng": lng},
        )
    ).one()
    dist = float(g.dist)
    if dist - min(accuracy_m, settings.accuracy_slack_m) > g.radius_m:
        await _reject(
            db,
            user,
            kind,
            "OUTSIDE_GEOFENCE",
            f"You're {dist:.0f} m from {g.name}. Move within {g.radius_m} m to mark attendance.",
            **ctx,
            dist=dist,
            status=403,
        )

    # 5. Soft signals -> accepted but flagged for review
    flags: list[str] = []
    prev = (
        await db.execute(
            text("""SELECT device_id,
                                            ST_Distance(location, ST_SetSRID(ST_MakePoint(:lng, :lat), 4326)::geography) AS d,
                                            EXTRACT(EPOCH FROM now() - created_at) AS secs
                                     FROM punch_attempts WHERE employee_id = :e AND accepted
                                     ORDER BY created_at DESC LIMIT 1"""),
            {"e": user.id, "lat": lat, "lng": lng},
        )
    ).first()
    if prev:
        if (
            prev.secs
            and prev.secs > 0
            and (prev.d / prev.secs) * 3.6 > settings.max_speed_kmh
        ):
            flags.append("IMPOSSIBLE_TRAVEL")
        if prev.device_id and prev.device_id != device_id:
            flags.append("DEVICE_CHANGED")
    if accuracy_m > 50:
        flags.append("MODERATE_ACCURACY")

    # 6. Liveness (server-side verdict)
    data = await photo.read(settings.max_photo_bytes + 1)
    if len(data) > settings.max_photo_bytes:
        await _reject(
            db,
            user,
            kind,
            "PHOTO_TOO_LARGE",
            "The photo is too large. Try again.",
            **ctx,
            dist=dist,
            status=413,
        )
    score = await verify_liveness(data, str(challenge))
    if score < settings.liveness_min_score:
        await _reject(
            db,
            user,
            kind,
            "LIVENESS_FAILED",
            "We couldn't confirm it's you. Face the camera in good light and retry.",
            **ctx,
            dist=dist,
        )
    photo_key = store_photo(user.id, kind.lower(), data)

    point = "ST_SetSRID(ST_MakePoint(:lng, :lat), 4326)::geography"
    params = dict(
        e=user.id,
        lat=lat,
        lng=lng,
        dist=dist,
        acc=accuracy_m,
        pk=photo_key,
        live=score,
        dev=device_id,
        ip=user.ip,
        flags=json.dumps(flags),
        review=bool(flags),
    )

    # 7. Write. Timestamps come from the DB trigger; nothing time-related is accepted from the client.
    if kind == "IN":
        try:
            row = (
                await db.execute(
                    text(f"""
                INSERT INTO attendance_sessions
                    (employee_id, shift_id, office_id, shift_date, clock_in_at, in_location, in_distance_m, in_accuracy_m,
                     in_photo_key, in_liveness, in_device_id, in_ip, flags, needs_review)
                SELECT e.id, e.shift_id, e.office_id, current_date, now(), {point}, :dist, :acc, :pk, :live, :dev,
                       CAST(:ip AS inet), CAST(:flags AS jsonb), :review
                FROM employees e WHERE e.id = :e
                RETURNING id, clock_in_at AS at, shift_date"""),
                    params,
                )
            ).one()
        except Exception as exc:
            if "one_open_session_per_employee" in str(exc):
                await db.rollback()
                raise err(
                    409,
                    "ALREADY_PUNCHED_IN",
                    "You're already punched in. Mark punch-out instead.",
                )
            raise
    else:
        row = (
            await db.execute(
                text(f"""
            UPDATE attendance_sessions SET clock_out_at = now(), out_location = {point}, out_distance_m = :dist,
                   out_accuracy_m = :acc, out_photo_key = :pk, out_liveness = :live, out_device_id = :dev,
                   out_ip = CAST(:ip AS inet),
                   flags = flags || CAST(:flags AS jsonb), needs_review = needs_review OR :review
            WHERE employee_id = :e AND clock_out_at IS NULL
            RETURNING id, clock_out_at AS at, shift_date"""),
                params,
            )
        ).first()
        if not row:
            raise err(409, "NOT_PUNCHED_IN", "You haven't punched in yet.")

    await db.execute(
        text(
            f"""INSERT INTO punch_attempts (employee_id, kind, accepted, location, accuracy_m, distance_m, device_id, ip)
                              VALUES (:e, CAST(:k AS punch_kind), true, {point}, :acc, :dist, :dev, CAST(:ip AS inet))"""
        ),
        {
            **{
                k: v
                for k, v in params.items()
                if k in ("e", "lat", "lng", "acc", "dist", "dev", "ip")
            },
            "k": kind,
        },
    )
    await audit(
        db,
        user.id,
        f"PUNCH_{kind}",
        entity="attendance_session",
        entity_id=str(row.id),
        meta={"flags": flags, "distance_m": round(dist, 1)},
        ip=user.ip,
    )
    return {
        "kind": kind,
        "server_time": row.at.isoformat(),
        "shift_date": row.shift_date.isoformat(),
        "flagged_for_review": bool(flags),
    }


PUNCH_FORM = dict(
    lat=Form(..., ge=-90, le=90),
    lng=Form(..., ge=-180, le=180),
    accuracy_m=Form(..., ge=0, le=100000),
    is_mock=Form(False),
    device_id=Form(..., min_length=8, max_length=128),
    challenge=Form(...),
)


@router.post("/attendance/punch-in")
async def punch_in(
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    photo: UploadFile = File(...),
    lat: float = PUNCH_FORM["lat"],
    lng: float = PUNCH_FORM["lng"],
    accuracy_m: float = PUNCH_FORM["accuracy_m"],
    is_mock: bool = PUNCH_FORM["is_mock"],
    device_id: str = PUNCH_FORM["device_id"],
    challenge: UUID = PUNCH_FORM["challenge"],
):
    return await _punch(
        "IN",
        user,
        db,
        lat=lat,
        lng=lng,
        accuracy_m=accuracy_m,
        is_mock=is_mock,
        device_id=device_id,
        challenge=challenge,
        photo=photo,
    )


@router.post("/attendance/punch-out")
async def punch_out(
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
    photo: UploadFile = File(...),
    lat: float = PUNCH_FORM["lat"],
    lng: float = PUNCH_FORM["lng"],
    accuracy_m: float = PUNCH_FORM["accuracy_m"],
    is_mock: bool = PUNCH_FORM["is_mock"],
    device_id: str = PUNCH_FORM["device_id"],
    challenge: UUID = PUNCH_FORM["challenge"],
):
    return await _punch(
        "OUT",
        user,
        db,
        lat=lat,
        lng=lng,
        accuracy_m=accuracy_m,
        is_mock=is_mock,
        device_id=device_id,
        challenge=challenge,
        photo=photo,
    )


@router.get("/attendance/status")
async def attendance_status(
    user: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    o = (
        await db.execute(
            text("""SELECT o.name, o.address, o.timezone, o.radius_m,
                                         ST_Y(o.location::geometry) AS lat, ST_X(o.location::geometry) AS lng,
                                         s.name AS shift_name, clock_timestamp() AS server_now
                                  FROM employees e JOIN offices o ON o.id = e.office_id JOIN shifts s ON s.id = e.shift_id
                                  WHERE e.id = :e"""),
            {"e": user.id},
        )
    ).one()
    last = (
        await db.execute(
            text(
                """SELECT clock_in_at, clock_out_at FROM attendance_sessions
                                     WHERE employee_id = :e ORDER BY clock_in_at DESC LIMIT 1"""
            ),
            {"e": user.id},
        )
    ).first()
    open_now = bool(last and last.clock_out_at is None)
    last_at = None
    if last:
        last_at = (last.clock_in_at if open_now else last.clock_out_at).isoformat()
    return {
        "server_now": o.server_now.isoformat(),  # UI clock is display-only, synced to this
        "punched_in": open_now,
        "since": last.clock_in_at.isoformat() if open_now else None,
        "last_punch_at": last_at,
        "last_punch_kind": None if not last else ("IN" if open_now else "OUT"),
        "shift": o.shift_name,
        "office": {
            "name": o.name,
            "address": o.address,
            "timezone": o.timezone,
            "lat": o.lat,
            "lng": o.lng,
            "radius_m": o.radius_m,
        },
    }


# ======================================================================
# LOGS, SUMMARY, DYNAMIC HOURS / MINUTES / SECONDS
# ======================================================================
@router.get("/attendance/logs")
async def attendance_logs(
    month: str = Query(..., pattern=r"^\d{4}-(0[1-9]|1[0-2])$"),
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    y, m = map(int, month.split("-"))
    d_from = date(y, m, 1)
    d_to = date(y + (m == 12), m % 12 + 1, 1) - timedelta(days=1)
    rows = await fetch_daily_rows(db, d_from, d_to, employee_id=user.id)
    return {
        "month": month,
        "tz": rows[0].tz if rows else "Asia/Kolkata",
        "summary": summarize(rows),
        "days": [day_to_json(r) for r in reversed(rows)],
    }


async def _resolve_scope(
    user: CurrentUser, db: AsyncSession, scope: str, employee_id: UUID | None
):
    """Returns (employee_id, manager_id) filters that the caller is allowed to use."""
    if user.role in ("ADMIN", "AUDITOR"):
        return (employee_id, None)
    if user.role == "MANAGER":
        if employee_id and employee_id != user.id:
            ok = (
                await db.execute(
                    text("SELECT 1 FROM employees WHERE id = :i AND manager_id = :m"),
                    {"i": employee_id, "m": user.id},
                )
            ).first()
            if not ok:
                raise err(403, "FORBIDDEN", "That employee isn't on your team.")
            return (employee_id, None)
        if scope == "team" and not employee_id:
            return (None, user.id)
    if employee_id and employee_id != user.id:
        raise err(403, "FORBIDDEN", "You can only view your own attendance.")
    return (user.id, None)


@router.get("/attendance/summary")
async def attendance_summary(
    from_: date = Query(..., alias="from"),
    to: date = Query(...),
    employee_id: UUID | None = None,
    scope: Literal["self", "team", "all"] = "self",
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    """Exact total hours, minutes and seconds for any date range (by shift date)."""
    if to < from_ or (to - from_).days > 366:
        raise err(422, "BAD_RANGE", "Choose a range of up to 366 days.")
    emp, mgr = await _resolve_scope(user, db, scope, employee_id)
    rows = await fetch_daily_rows(db, from_, to, employee_id=emp, manager_id=mgr)
    return {"from": from_.isoformat(), "to": to.isoformat(), **summarize(rows)}


# ======================================================================
# EXCEL EXPORT
# ======================================================================
@router.get("/export/attendance.xlsx")
async def export_attendance(
    from_: date = Query(..., alias="from"),
    to: date = Query(...),
    employee_id: UUID | None = None,
    scope: Literal["self", "team", "all"] = "self",
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    if to < from_ or (to - from_).days > 366:
        raise err(422, "BAD_RANGE", "Choose a range of up to 366 days.")
    emp, mgr = await _resolve_scope(user, db, scope, employee_id)
    if scope == "all" and user.role not in ("ADMIN", "AUDITOR"):
        raise err(403, "FORBIDDEN", "Only admins can export the whole company.")
    rows = await fetch_daily_rows(db, from_, to, employee_id=emp, manager_id=mgr)
    who = (
        await db.execute(
            text("SELECT full_name FROM employees WHERE id = :i"), {"i": user.id}
        )
    ).scalar_one()
    blob = build_workbook(rows, from_, to, generated_by=who)
    await audit(
        db,
        user.id,
        "EXPORT_ATTENDANCE",
        entity="attendance",
        meta={
            "from": str(from_),
            "to": str(to),
            "scope": scope,
            "employee_id": str(emp) if emp else None,
            "rows": len(rows),
        },
        ip=user.ip,
    )
    name = f"attendance_{from_:%Y%m%d}_{to:%Y%m%d}.xlsx"
    return StreamingResponse(
        iter([blob]),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


# ======================================================================
# PROFILE VAULT (encrypted at the application layer)
# ======================================================================
class Vault(BaseModel):
    full_name: str | None = Field(None, max_length=120)
    dob: date | None = None
    mobile: str | None = None
    personal_email: EmailStr | None = None
    gender: Literal["Male", "Female", "Other", "Prefer not to say"] | None = None
    pan: str | None = None
    aadhaar: str | None = None

    @field_validator("mobile")
    @classmethod
    def _mobile(cls, v):
        if v and not re.fullmatch(r"[6-9]\d{9}", v):
            raise ValueError("Enter a 10-digit mobile number.")
        return v

    @field_validator("pan")
    @classmethod
    def _pan(cls, v):
        if v and not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", v.upper()):
            raise ValueError("PAN looks like ABCDE1234F.")
        return v.upper() if v else v

    @field_validator("aadhaar")
    @classmethod
    def _aadhaar(cls, v):
        if v and not re.fullmatch(r"\d{12}", v):
            raise ValueError("Aadhaar has 12 digits.")
        return v


def _mask(v: str | None) -> str | None:
    return None if not v else "X" * (len(v) - 4) + v[-4:]


@router.get("/profile/vault")
async def get_vault(
    reveal: bool = False,
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(
            text("SELECT ciphertext FROM employee_vault WHERE employee_id = :i"),
            {"i": user.id},
        )
    ).first()
    data = vault_decrypt(user.id, row.ciphertext) if row else {}
    if reveal:
        await audit(
            db,
            user.id,
            "VAULT_REVEAL",
            entity="employee_vault",
            entity_id=str(user.id),
            ip=user.ip,
        )
    else:
        data = {
            **data,
            "pan": _mask(data.get("pan")),
            "aadhaar": _mask(data.get("aadhaar")),
        }
    return data


@router.put("/profile/vault")
async def put_vault(
    body: Vault,
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(
            text("SELECT ciphertext FROM employee_vault WHERE employee_id = :i"),
            {"i": user.id},
        )
    ).first()
    current = vault_decrypt(user.id, row.ciphertext) if row else {}
    current.update(
        {
            k: (v.isoformat() if isinstance(v, date) else v)
            for k, v in body.model_dump(exclude_unset=True).items()
        }
    )
    await db.execute(
        text(
            """INSERT INTO employee_vault (employee_id, ciphertext) VALUES (:i, :c)
                             ON CONFLICT (employee_id) DO UPDATE SET ciphertext = :c, updated_at = now()"""
        ),
        {"i": user.id, "c": vault_encrypt(user.id, current)},
    )
    await audit(
        db,
        user.id,
        "VAULT_UPDATE",
        entity="employee_vault",
        entity_id=str(user.id),
        meta={"fields": list(body.model_dump(exclude_unset=True))},
        ip=user.ip,
    )
    return {"ok": True}


# ======================================================================
# FEED
# ======================================================================
@router.get("/feed")
async def feed(
    user: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    rows = (
        await db.execute(
            text("""
        SELECT p.id, p.kind, p.title, p.body, p.created_at, a.full_name AS about,
               (SELECT count(*) FROM feed_likes l WHERE l.post_id = p.id) AS likes,
               EXISTS (SELECT 1 FROM feed_likes l WHERE l.post_id = p.id AND l.employee_id = :e) AS liked
        FROM feed_posts p LEFT JOIN employees a ON a.id = p.about_id
        ORDER BY p.created_at DESC LIMIT 20"""),
            {"e": user.id},
        )
    ).all()
    return [
        {
            "id": str(r.id),
            "kind": r.kind,
            "title": r.title,
            "body": r.body,
            "about": r.about,
            "created_at": r.created_at.isoformat(),
            "likes": r.likes,
            "liked": r.liked,
        }
        for r in rows
    ]


@router.post("/feed/{post_id}/like")
async def toggle_like(
    post_id: UUID,
    user: CurrentUser = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    gone = (
        await db.execute(
            text(
                "DELETE FROM feed_likes WHERE post_id = :p AND employee_id = :e RETURNING 1"
            ),
            {"p": post_id, "e": user.id},
        )
    ).first()
    if not gone:
        await db.execute(
            text("INSERT INTO feed_likes VALUES (:p, :e) ON CONFLICT DO NOTHING"),
            {"p": post_id, "e": user.id},
        )
    return {"liked": not gone}


# ======================================================================
# ADMIN
# ======================================================================
@router.get("/admin/audit-logs")
async def audit_logs(
    limit: int = Query(100, le=500),
    before_id: int | None = None,
    user: CurrentUser = Depends(require_role("ADMIN", "AUDITOR")),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        (
            await db.execute(
                text(
                    """SELECT id, actor_id, action, entity, entity_id, meta, ip::text AS ip, created_at
                                     FROM audit_logs WHERE (CAST(:b AS bigint) IS NULL OR id < CAST(:b AS bigint))
                                     ORDER BY id DESC LIMIT :l"""
                ),
                {"b": before_id, "l": limit},
            )
        )
        .mappings()
        .all()
    )
    broken = (await db.execute(text("SELECT verify_audit_chain()"))).scalar()
    return {
        "chain_intact": broken is None,
        "first_broken_id": broken,
        "items": [
            {
                **dict(r),
                "actor_id": str(r["actor_id"]) if r["actor_id"] else None,
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ],
    }


@router.get("/")
async def read_index():
    return FileResponse("index.html")
