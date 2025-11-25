from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError
import os
from dotenv import load_dotenv

def run():
    print("🚀 Running migrations.012_update_wiring_equipment_columns")

    load_dotenv()
    mysql_url = os.getenv("MYSQL_URL")

    engine = create_engine(mysql_url)
    conn = engine.connect()
    table_name = "wiring_equipment_data"

    # 1️⃣ Rename panel_id → instance_id
    try:
        conn.execute(text(f"ALTER TABLE {table_name} CHANGE COLUMN panel_id instance_id VARCHAR(100) NOT NULL;"))
        print("✅ Renamed column panel_id → instance_id")
    except ProgrammingError as e:
        print(f"⚠ Skipping rename: {e}")

    # 2️⃣ Add floor_name if not exists
    try:
        conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN floor_name VARCHAR(100) NOT NULL DEFAULT 'Null';"))
        print("✅ Added floor_name column")
    except ProgrammingError as e:
        print(f"⚠ Skipping floor_name addition: {e}")

    conn.close()
    print("✅ Completed migrations.012_update_wiring_equipment_columns")
