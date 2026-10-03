-- =====================================================================
-- Attendance & HR Management System : PostgreSQL 15+ / PostGIS 3
-- Run:  psql "$DATABASE_URL" -f schema.sql
-- =====================================================================
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TYPE user_role      AS ENUM ('EMPLOYEE', 'MANAGER', 'ADMIN', 'AUDITOR');
CREATE TYPE punch_kind     AS ENUM ('IN', 'OUT');
CREATE TYPE request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED');
CREATE TYPE feed_kind      AS ENUM ('ANNOUNCEMENT', 'BIRTHDAY', 'CELEBRATION');

-- ---------------------------------------------------------------------
-- Organisation structure
-- ---------------------------------------------------------------------
CREATE TABLE offices (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    address    text,
    timezone   text        NOT NULL DEFAULT 'Asia/Kolkata',
    location   geography(Point, 4326) NOT NULL,
    radius_m   integer     NOT NULL DEFAULT 150 CHECK (radius_m BETWEEN 20 AND 5000),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX offices_location_gix ON offices USING gist (location);

CREATE TABLE shifts (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text    NOT NULL,
    start_time       time    NOT NULL,
    end_time         time    NOT NULL,
    -- 22:00 -> 06:00 is a night shift: end <= start means it ends the next day
    crosses_midnight boolean GENERATED ALWAYS AS (end_time <= start_time) STORED,
    standard_minutes integer NOT NULL DEFAULT 480 CHECK (standard_minutes > 0),   -- 8 hours
    weekly_off       smallint[] NOT NULL DEFAULT '{0}'                             -- 0 = Sunday
);

CREATE TABLE holidays (
    holiday_date date PRIMARY KEY,
    name         text NOT NULL
);

-- ---------------------------------------------------------------------
-- Employees & auth
-- ---------------------------------------------------------------------
CREATE TABLE employees (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    emp_code      text        NOT NULL UNIQUE,
    full_name     text        NOT NULL,
    email         citext      NOT NULL UNIQUE,
    password_hash text        NOT NULL,                         -- argon2id
    role          user_role   NOT NULL DEFAULT 'EMPLOYEE',
    office_id     uuid        NOT NULL REFERENCES offices(id),
    shift_id      uuid        NOT NULL REFERENCES shifts(id),
    manager_id    uuid        REFERENCES employees(id),
    joined_on     date        NOT NULL DEFAULT current_date,
    is_active     boolean     NOT NULL DEFAULT true,
    failed_logins smallint    NOT NULL DEFAULT 0,
    locked_until  timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX employees_manager_idx ON employees (manager_id);

-- Encrypted profile vault. The application encrypts with AES-256-GCM BEFORE
-- writing; the database only ever sees ciphertext (DOB, mobile, PAN, Aadhaar...).
CREATE TABLE employee_vault (
    employee_id uuid PRIMARY KEY REFERENCES employees(id) ON DELETE CASCADE,
    ciphertext  bytea       NOT NULL,          -- 12-byte nonce || ciphertext || tag
    key_version smallint    NOT NULL DEFAULT 1,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
-- Attendance
-- ---------------------------------------------------------------------
-- One row per continuous duty session. A night shift is ONE row whose
-- shift_date is the day the shift STARTED, so it is never split across
-- calendar days.
CREATE TABLE attendance_sessions (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id    uuid        NOT NULL REFERENCES employees(id),
    shift_id       uuid        NOT NULL REFERENCES shifts(id),
    office_id      uuid        NOT NULL REFERENCES offices(id),
    shift_date     date        NOT NULL,                       -- set by trigger
    clock_in_at    timestamptz NOT NULL,                       -- set by trigger (server clock)
    clock_out_at   timestamptz,                                -- set by trigger (server clock)

    in_location    geography(Point, 4326) NOT NULL,
    in_distance_m  real        NOT NULL,
    in_accuracy_m  real,
    in_photo_key   text,
    in_liveness    real,
    in_device_id   text,
    in_ip          inet,

    out_location   geography(Point, 4326),
    out_distance_m real,
    out_accuracy_m real,
    out_photo_key  text,
    out_liveness   real,
    out_device_id  text,
    out_ip         inet,

    needs_review   boolean     NOT NULL DEFAULT false,         -- soft anti-spoof flags
    flags          jsonb       NOT NULL DEFAULT '[]'::jsonb,
    source         text        NOT NULL DEFAULT 'APP' CHECK (source IN ('APP', 'REGULARIZATION')),
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT clock_order CHECK (clock_out_at IS NULL OR clock_out_at > clock_in_at)
);
CREATE UNIQUE INDEX one_open_session_per_employee
    ON attendance_sessions (employee_id) WHERE clock_out_at IS NULL;
CREATE INDEX attendance_emp_date_idx ON attendance_sessions (employee_id, shift_date);
CREATE INDEX attendance_date_idx     ON attendance_sessions (shift_date);

-- Every punch attempt, accepted or rejected (forensics + travel-speed checks)
CREATE TABLE punch_attempts (
    id          bigserial PRIMARY KEY,
    employee_id uuid        NOT NULL REFERENCES employees(id),
    kind        punch_kind  NOT NULL,
    accepted    boolean     NOT NULL,
    reason_code text,
    location    geography(Point, 4326),
    accuracy_m  real,
    distance_m  real,
    device_id   text,
    ip          inet,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX punch_attempts_emp_idx ON punch_attempts (employee_id, created_at DESC);

-- Single-use, short-lived challenge: binds one liveness capture to one punch
CREATE TABLE punch_challenges (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id uuid        NOT NULL REFERENCES employees(id),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz
);

-- ---------------------------------------------------------------------
-- HR requests & feed
-- ---------------------------------------------------------------------
CREATE TABLE leave_requests (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id uuid           NOT NULL REFERENCES employees(id),
    from_date   date           NOT NULL,
    to_date     date           NOT NULL CHECK (to_date >= from_date),
    reason      text,
    status      request_status NOT NULL DEFAULT 'PENDING',
    decided_by  uuid REFERENCES employees(id),
    created_at  timestamptz    NOT NULL DEFAULT now()
);

CREATE TABLE regularization_requests (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id  uuid           NOT NULL REFERENCES employees(id),
    for_date     date           NOT NULL,
    requested_in  timestamptz,
    requested_out timestamptz,
    reason       text           NOT NULL,
    status       request_status NOT NULL DEFAULT 'PENDING',
    decided_by   uuid REFERENCES employees(id),
    created_at   timestamptz    NOT NULL DEFAULT now()
);

CREATE TABLE feed_posts (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        feed_kind   NOT NULL,
    title       text        NOT NULL,
    body        text,
    about_id    uuid REFERENCES employees(id),   -- birthday / celebration subject
    created_by  uuid REFERENCES employees(id),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE feed_likes (
    post_id     uuid REFERENCES feed_posts(id) ON DELETE CASCADE,
    employee_id uuid REFERENCES employees(id)  ON DELETE CASCADE,
    PRIMARY KEY (post_id, employee_id)
);

-- =====================================================================
-- ANTI-TAMPER: the database owns the clock
-- =====================================================================
CREATE OR REPLACE FUNCTION resolve_shift_date(p_shift uuid, p_office uuid)
RETURNS date LANGUAGE plpgsql STABLE AS $$
DECLARE
    tz text;
    s  shifts%ROWTYPE;
    ln timestamp;
BEGIN
    SELECT timezone INTO tz FROM offices WHERE id = p_office;
    SELECT * INTO s FROM shifts WHERE id = p_shift;
    ln := clock_timestamp() AT TIME ZONE tz;
    -- A punch at 01:30 for a 22:00-06:00 shift belongs to the PREVIOUS calendar day.
    IF s.crosses_midnight AND ln::time < s.end_time THEN
        RETURN ln::date - 1;
    END IF;
    RETURN ln::date;
END $$;

CREATE OR REPLACE FUNCTION trg_attendance_server_time() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Approved regularizations run inside a transaction that sets
    -- SET LOCAL app.allow_manual_time = 'on' (and writes an audit row).
    IF current_setting('app.allow_manual_time', true) = 'on' THEN
        IF TG_OP = 'INSERT' AND NEW.shift_date IS NULL THEN
            NEW.shift_date := (NEW.clock_in_at AT TIME ZONE
                               (SELECT timezone FROM offices WHERE id = NEW.office_id))::date;
        END IF;
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        NEW.clock_in_at  := clock_timestamp();      -- client value, if any, is discarded
        NEW.clock_out_at := NULL;
        NEW.shift_date   := resolve_shift_date(NEW.shift_id, NEW.office_id);
    ELSE
        IF NEW.clock_in_at IS DISTINCT FROM OLD.clock_in_at
           OR NEW.employee_id <> OLD.employee_id
           OR NEW.shift_date  <> OLD.shift_date THEN
            RAISE EXCEPTION 'attendance identity/time fields are immutable';
        END IF;
        IF OLD.clock_out_at IS NOT NULL
           AND NEW.clock_out_at IS DISTINCT FROM OLD.clock_out_at THEN
            RAISE EXCEPTION 'session already closed';
        END IF;
        IF OLD.clock_out_at IS NULL AND NEW.clock_out_at IS NOT NULL THEN
            NEW.clock_out_at := clock_timestamp();
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER attendance_server_time
    BEFORE INSERT OR UPDATE ON attendance_sessions
    FOR EACH ROW EXECUTE FUNCTION trg_attendance_server_time();

CREATE OR REPLACE FUNCTION trg_block_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on % is not permitted', TG_OP, TG_TABLE_NAME;
END $$;

CREATE TRIGGER attendance_no_delete
    BEFORE DELETE OR TRUNCATE ON attendance_sessions
    FOR EACH STATEMENT EXECUTE FUNCTION trg_block_delete();

-- =====================================================================
-- IMMUTABLE ADMIN AUDIT LOG (append-only, hash-chained)
-- =====================================================================
CREATE TABLE audit_logs (
    id         bigserial   PRIMARY KEY,
    actor_id   uuid,
    action     text        NOT NULL,            -- e.g. LOGIN, PUNCH_IN, EXPORT, VAULT_READ
    entity     text,
    entity_id  text,
    meta       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ip         inet,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    prev_hash  bytea,
    row_hash   bytea
);

CREATE OR REPLACE FUNCTION trg_audit_chain() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    prev bytea;
BEGIN
    PERFORM pg_advisory_xact_lock(7001);          -- serialise the chain
    SELECT row_hash INTO prev FROM audit_logs ORDER BY id DESC LIMIT 1;
    NEW.prev_hash := COALESCE(prev, '\x00'::bytea);
    NEW.row_hash  := digest(
        NEW.prev_hash || convert_to(concat_ws('|', NEW.id, NEW.actor_id, NEW.action,
            NEW.entity, NEW.entity_id, NEW.meta::text, NEW.ip::text, NEW.created_at::text), 'UTF8'),
        'sha256');
    RETURN NEW;
END $$;

CREATE TRIGGER audit_chain      BEFORE INSERT ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION trg_audit_chain();
CREATE TRIGGER audit_no_update  BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION trg_block_delete();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION trg_block_delete();

-- Verify the chain any time (returns the first broken id, or NULL when intact)
CREATE OR REPLACE FUNCTION verify_audit_chain() RETURNS bigint
LANGUAGE sql STABLE AS $$
    SELECT id FROM (
        SELECT id, prev_hash, row_hash,
               lag(row_hash) OVER (ORDER BY id) AS expected_prev,
               digest(prev_hash || convert_to(concat_ws('|', id, actor_id, action,
                   entity, entity_id, meta::text, ip::text, created_at::text), 'UTF8'), 'sha256') AS recomputed
        FROM audit_logs
    ) t
    WHERE recomputed <> row_hash
       OR (expected_prev IS NOT NULL AND prev_hash <> expected_prev)
    ORDER BY id LIMIT 1;
$$;

-- Recommended role separation (adjust role names):
--   CREATE ROLE app_rw LOGIN PASSWORD '...';
--   GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_rw;
--   REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM app_rw;
--   REVOKE DELETE, TRUNCATE ON attendance_sessions FROM app_rw;

-- ---------------------------------------------------------------------
-- Reporting view (single source of truth for duration maths)
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_session_metrics AS
SELECT s.id, s.employee_id, s.shift_date, s.clock_in_at, s.clock_out_at,
       sh.standard_minutes * 60 AS standard_secs,
       -- open sessions count up to now(), capped at 16h so a forgotten punch-out cannot run away
       FLOOR(EXTRACT(EPOCH FROM (
           COALESCE(s.clock_out_at, LEAST(now(), s.clock_in_at + interval '16 hours')) - s.clock_in_at
       )))::bigint AS worked_secs
FROM attendance_sessions s
JOIN shifts sh ON sh.id = s.shift_id;

-- ---------------------------------------------------------------------
-- Sample seed (Delhi office, 9-to-6 day shift and 10pm-6am night shift)
-- ---------------------------------------------------------------------
INSERT INTO offices (name, address, location, radius_m)
VALUES ('Head Office', 'Connaught Place, New Delhi',
        ST_SetSRID(ST_MakePoint(77.2167, 28.6315), 4326)::geography, 150);
INSERT INTO shifts (name, start_time, end_time) VALUES
    ('General',      '09:00', '18:00'),
    ('Night',        '22:00', '06:00');
