"""Settings, database session, authentication, CSRF, vault encryption and audit logging."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import AsyncIterator, Callable
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/attendance"
    )
    jwt_secret: str  # 32+ random bytes
    csrf_secret: str  # different from jwt_secret
    vault_key_b64: str  # base64 of 32 random bytes (AES-256)
    access_ttl_minutes: int = 30
    cookie_secure: bool = True
    cookie_samesite: str = "lax"  # "strict" if the SPA is same-site
    cors_origins: list[str] = ["http://localhost:5173"]

    # Anti-spoofing thresholds
    max_accuracy_m: float = 100.0  # reject fixes worse than this
    accuracy_slack_m: float = 25.0  # max forgiveness applied to the geofence edge
    max_speed_kmh: float = 250.0  # implausible travel between two accepted punches
    liveness_min_score: float = 0.85
    challenge_ttl_seconds: int = 120
    max_photo_bytes: int = 2_000_000
    photo_dir: str = "./photos"  # swap for S3/GCS with server-side encryption


settings = Settings()  # type: ignore[call-arg]
app = FastAPI()


engine = create_async_engine(settings.database_url, pool_pre_ping=True, pool_size=10)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# --------------------------------------------------------------------------
# Passwords + tokens
# --------------------------------------------------------------------------
pwd = CryptContext(schemes=["argon2"], deprecated="auto")
ALGO = "HS256"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def issue_token(emp_id: UUID, role: str) -> tuple[str, str]:
    jti = secrets.token_hex(16)
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.access_ttl_minutes)
    token = jwt.encode(
        {"sub": str(emp_id), "role": role, "jti": jti, "exp": exp},
        settings.jwt_secret,
        algorithm=ALGO,
    )
    return token, jti


def csrf_for(sub: str, jti: str) -> str:
    """CSRF token is an HMAC bound to this login, so it can't be reused across sessions."""
    return hmac.new(
        settings.csrf_secret.encode(), f"{sub}:{jti}".encode(), hashlib.sha256
    ).hexdigest()


@dataclass
class CurrentUser:
    id: UUID
    role: str
    jti: str
    ip: str | None


def client_ip(request: Request) -> str | None:
    # Only trust X-Forwarded-For if your reverse proxy overwrites it.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


async def current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> CurrentUser:
    bearer = request.headers.get("authorization", "")
    via_cookie = not bearer.lower().startswith("bearer ")
    token = request.cookies.get("access_token") if via_cookie else bearer[7:]
    if not token:
        raise HTTPException(
            401, {"code": "UNAUTHENTICATED", "message": "Please sign in."}
        )
    try:
        claims = jwt.decode(token, settings.jwt_secret, algorithms=[ALGO])
    except JWTError:
        raise HTTPException(
            401,
            {
                "code": "TOKEN_INVALID",
                "message": "Your session has expired. Sign in again.",
            },
        )

    # CSRF: cookie-authenticated, state-changing requests need the matching header.
    if via_cookie and request.method not in SAFE_METHODS:
        header = request.headers.get("x-csrf-token", "")
        expected = csrf_for(claims["sub"], claims["jti"])
        if not (
            hmac.compare_digest(header, expected)
            and hmac.compare_digest(request.cookies.get("csrf_token", ""), expected)
        ):
            raise HTTPException(
                403,
                {
                    "code": "CSRF",
                    "message": "Security check failed. Reload and try again.",
                },
            )

    row = (
        await db.execute(
            text("SELECT is_active FROM employees WHERE id = CAST(:i AS uuid)"),
            {"i": claims["sub"]},
        )
    ).first()
    if not row or not row.is_active:
        raise HTTPException(
            401, {"code": "INACTIVE", "message": "This account is disabled."}
        )
    return CurrentUser(
        UUID(claims["sub"]), claims["role"], claims["jti"], client_ip(request)
    )


def require_role(*roles: str) -> Callable[..., CurrentUser]:
    async def dep(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if user.role not in roles:
            raise HTTPException(
                403, {"code": "FORBIDDEN", "message": "You don't have access to this."}
            )
        return user

    return dep


# --------------------------------------------------------------------------
# Vault encryption (AES-256-GCM, employee id bound as associated data)
# --------------------------------------------------------------------------
def _vault() -> AESGCM:
    return AESGCM(base64.b64decode(settings.vault_key_b64))


def vault_encrypt(emp_id: UUID, payload: dict) -> bytes:
    nonce = os.urandom(12)
    return nonce + _vault().encrypt(
        nonce, json.dumps(payload).encode(), str(emp_id).encode()
    )


def vault_decrypt(emp_id: UUID, blob: bytes) -> dict:
    nonce, ct = bytes(blob[:12]), bytes(blob[12:])
    return json.loads(_vault().decrypt(nonce, ct, str(emp_id).encode()))


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------
async def audit(
    db: AsyncSession,
    actor: UUID | None,
    action: str,
    *,
    entity: str | None = None,
    entity_id: str | None = None,
    meta: dict | None = None,
    ip: str | None = None,
) -> None:
    await db.execute(
        text(
            """INSERT INTO audit_logs (actor_id, action, entity, entity_id, meta, ip)
                VALUES (CAST(:a AS uuid), :act, :ent, :eid, CAST(:m AS jsonb), CAST(:ip AS inet))"""
        ),
        {
            "a": str(actor) if actor else None,
            "act": action,
            "ent": entity,
            "eid": entity_id,
            "m": json.dumps(meta or {}),
            "ip": ip,
        },
    )


@app.get("/")
async def read_index():
    return FileResponse("index.html")


from routes import router

app.include_router(router)
