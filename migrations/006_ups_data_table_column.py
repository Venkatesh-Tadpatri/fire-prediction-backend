from models import Base, UPSData
from database import engine
from sqlalchemy import text

# def run():
#     print("📦 Running migration: Create ups_data table")
#     Base.metadata.create_all(bind=engine, tables=[UPSData.__table__])
#     print("✅ ups_data table created successfully")


def run():
    with engine.connect() as conn:
        print("📦 Adding risk columns to ups_data table safely")

        # Check and add risk_score
        result = conn.execute(text("SHOW COLUMNS FROM ups_data LIKE 'risk_score';"))
        if not result.first():
            conn.execute(text('ALTER TABLE ups_data ADD COLUMN risk_score FLOAT DEFAULT 0;'))
            print("✅ Added column: risk_score")
        else:
            print("⚠ Column risk_score already exists")

        # Check and add risk_level
        result = conn.execute(text("SHOW COLUMNS FROM ups_data LIKE 'risk_level';"))
        if not result.first():
            conn.execute(text("ALTER TABLE ups_data ADD COLUMN risk_level VARCHAR(20) DEFAULT 'Normal';"))
            print("✅ Added column: risk_level")
        else:
            print("⚠ Column risk_level already exists")

        # Check and add risk_created_at
        result = conn.execute(text("SHOW COLUMNS FROM ups_data LIKE 'risk_created_at';"))
        if not result.first():
            conn.execute(text("ALTER TABLE ups_data ADD COLUMN risk_created_at DATETIME DEFAULT CURRENT_TIMESTAMP;"))
            print("✅ Added column: risk_created_at")
        else:
            print("⚠ Column risk_created_at already exists")

        print("✅ Risk columns migration completed successfully")

if __name__ == "__main__":
    run()
