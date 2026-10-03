"""Single source of truth for attendance duration maths.

Rules
-----
* Standard shift = shift.standard_minutes (default 480 = 8 h).
* Anything worked beyond the standard duration on a shift_date is overtime.
* A night shift is ONE session whose shift_date is the day it started, so
  22:00 -> 06:00 is one 8 h day, never two partial days.
* Open sessions count up to "now" (capped at 16 h in SQL).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def split_hms(total_seconds: int) -> dict:
    total = max(int(total_seconds), 0)
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return {"hours": h, "minutes": m, "seconds": s, "total_seconds": total,
            "total_minutes": total // 60, "hhmmss": f"{h:02d}:{m:02d}:{s:02d}"}


def duration_label(total_seconds: int) -> str:
    h, rem = divmod(max(int(total_seconds), 0), 3600)
    return f"{h}hr {rem // 60}min"


def split_overtime(worked: int, standard: int) -> tuple[int, int]:
    return min(worked, standard), max(worked - standard, 0)


DAILY_SQL = text("""
WITH cal AS (
    SELECT e.id AS employee_id, e.emp_code, e.full_name, e.shift_id, e.office_id, d::date AS day
    FROM employees e
    CROSS JOIN LATERAL generate_series(
        GREATEST(CAST(:d_from AS date), e.joined_on)::timestamp,
        CAST(:d_to AS date)::timestamp,
        interval '1 day') AS d
    WHERE e.is_active
      AND (CAST(:emp AS uuid) IS NULL OR e.id = CAST(:emp AS uuid))
      AND (CAST(:mgr AS uuid) IS NULL OR e.manager_id = CAST(:mgr AS uuid))
), agg AS (
    SELECT m.employee_id, m.shift_date,
           MIN(m.clock_in_at)                AS first_in,
           MAX(m.clock_out_at)               AS last_out,
           BOOL_OR(m.clock_out_at IS NULL)   AS is_open,
           SUM(m.worked_secs)::bigint        AS worked_secs,
           BOOL_OR(s.needs_review)           AS needs_review
    FROM v_session_metrics m
    JOIN attendance_sessions s ON s.id = m.id
    WHERE m.shift_date BETWEEN CAST(:d_from AS date) AND CAST(:d_to AS date)
    GROUP BY m.employee_id, m.shift_date
)
SELECT cal.employee_id, cal.emp_code, cal.full_name, cal.day,
       sh.name AS shift_name,
       to_char(sh.start_time, 'HH24:MI') || '-' || to_char(sh.end_time, 'HH24:MI') AS shift_range,
       sh.crosses_midnight,
       sh.standard_minutes * 60 AS standard_secs,
       o.timezone AS tz,
       (now() AT TIME ZONE o.timezone)::date AS local_today,
       agg.first_in, agg.last_out,
       COALESCE(agg.is_open, false)      AS is_open,
       COALESCE(agg.worked_secs, 0)      AS worked_secs,
       COALESCE(agg.needs_review, false) AS needs_review,
       EXISTS (SELECT 1 FROM holidays h WHERE h.holiday_date = cal.day)            AS is_holiday,
       (EXTRACT(DOW FROM cal.day)::int = ANY (sh.weekly_off))                      AS is_weekly_off,
       EXISTS (SELECT 1 FROM leave_requests l
               WHERE l.employee_id = cal.employee_id AND l.status = 'APPROVED'
                 AND cal.day BETWEEN l.from_date AND l.to_date)                    AS on_leave
FROM cal
JOIN shifts  sh ON sh.id = cal.shift_id
JOIN offices o  ON o.id  = cal.office_id
LEFT JOIN agg ON agg.employee_id = cal.employee_id AND agg.shift_date = cal.day
WHERE cal.day <= (now() AT TIME ZONE o.timezone)::date
ORDER BY cal.day, cal.emp_code
""")


@dataclass
class DayRow:
    employee_id: UUID
    emp_code: str
    full_name: str
    day: date
    shift_name: str
    shift_range: str
    crosses_midnight: bool
    tz: str
    status: str
    first_in: datetime | None
    last_out: datetime | None
    is_open: bool
    worked: int
    standard: int
    overtime: int
    needs_review: bool


def _status(r) -> str:
    if r.first_in is not None:
        return "PENDING" if r.needs_review else "PRESENT"
    if r.on_leave:
        return "LEAVE"
    if r.is_holiday:
        return "HOLIDAY"
    if r.is_weekly_off:
        return "WEEK_OFF"
    if r.day == r.local_today:
        return "PENDING"          # today, not marked yet
    return "ABSENT"


async def fetch_daily_rows(db: AsyncSession, d_from: date, d_to: date, *,
                           employee_id: UUID | None = None,
                           manager_id: UUID | None = None) -> list[DayRow]:
    res = await db.execute(DAILY_SQL, {
        "d_from": d_from, "d_to": d_to,
        "emp": str(employee_id) if employee_id else None,
        "mgr": str(manager_id) if manager_id else None,
    })
    out: list[DayRow] = []
    for r in res.all():
        std_part, ot = split_overtime(int(r.worked_secs), int(r.standard_secs))
        out.append(DayRow(
            employee_id=r.employee_id, emp_code=r.emp_code, full_name=r.full_name, day=r.day,
            shift_name=r.shift_name, shift_range=r.shift_range, crosses_midnight=r.crosses_midnight,
            tz=r.tz, status=_status(r), first_in=r.first_in, last_out=r.last_out,
            is_open=r.is_open, worked=int(r.worked_secs), standard=std_part, overtime=ot,
            needs_review=r.needs_review,
        ))
    return out


def summarize(rows: list[DayRow]) -> dict:
    worked = sum(r.worked for r in rows)
    ot = sum(r.overtime for r in rows)
    std = sum(r.standard for r in rows)
    return {
        "present_days": sum(1 for r in rows if r.first_in is not None),
        "absent_days": sum(1 for r in rows if r.status == "ABSENT"),
        "working_days": sum(1 for r in rows
                            if r.first_in is not None or r.status not in ("HOLIDAY", "WEEK_OFF", "LEAVE")),
        "total": split_hms(worked),
        "standard": split_hms(std),
        "overtime": split_hms(ot),
    }


def day_to_json(r: DayRow) -> dict:
    return {
        "date": r.day.isoformat(),
        "status": r.status,
        "shift": r.shift_name,
        "shift_range": r.shift_range,
        "first_in": r.first_in.isoformat() if r.first_in else None,
        "last_out": r.last_out.isoformat() if r.last_out else None,
        "is_open": r.is_open,
        "crosses_midnight": r.crosses_midnight,
        "worked_seconds": r.worked,
        "overtime_seconds": r.overtime,
        "duration_label": duration_label(r.worked),
    }
