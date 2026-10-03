import asyncio
from core import SessionLocal, pwd
import sqlalchemy as sa


async def fix():
    async with SessionLocal() as session:
        try:
            # 1. Tables ensure karo
            await session.execute(sa.text("""
                CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    password_hash TEXT,
                    full_name TEXT,
                    role TEXT,
                    is_active BOOLEAN,
                    failed_logins INTEGER,
                    locked_until TIMESTAMP
                )
            """))

            await session.execute(sa.text("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_id TEXT,
                    action TEXT,
                    entity TEXT,
                    entity_id TEXT,
                    meta TEXT,
                    ip TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))

            # 2. Puraana admin hata kar naya daalo
            await session.execute(
                sa.text("DELETE FROM employees WHERE email = 'admin@example.com'")
            )

            await session.execute(
                sa.text("""
                    INSERT INTO employees 
                    (email, password_hash, full_name, role, is_active, failed_logins)
                    VALUES ('admin@example.com', :pwd, 'Administrator', 'admin', 1, 0)
                """),
                {"pwd": pwd.hash("admin123")},
            )

            await session.commit()
            print("SUCCESS: Admin Fixed successfully!")
        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    asyncio.run(fix())
