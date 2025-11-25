# fire_prediction_backend/migrations/004_add_user_password_columns.py

from sqlalchemy import MetaData, Table, text
from database import engine

def run():
    print("🚀 Running migration: Add otp, otp_expiry, otp_status columns to users")

    metadata = MetaData()
    metadata.reflect(bind=engine)

    users = Table("users", metadata, autoload_with=engine)

    with engine.connect() as conn:
        # Add otp column
        if "otp" not in users.c:
            conn.execute(text("ALTER TABLE users ADD COLUMN otp VARCHAR(6) NULL"))

        # Add otp_expiry column
        if "otp_expiry" not in users.c:
            conn.execute(text("ALTER TABLE users ADD COLUMN otp_expiry DATETIME NULL"))

        # Add otp_status column
        if "otp_status" not in users.c:
            conn.execute(text("ALTER TABLE users ADD COLUMN otp_status BOOLEAN DEFAULT 0"))

    print("✅ Completed migration: otp, otp_expiry, otp_status added to users table")
