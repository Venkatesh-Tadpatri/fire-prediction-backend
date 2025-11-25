from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import os
from dotenv import load_dotenv

def run():
    print("📦 Running migration: 014_add_grid_number_column_to_components_layout")

    load_dotenv()
    mysql_url = os.getenv("MYSQL_URL")

    engine = create_engine(mysql_url)
    conn = engine.connect()
    table_name = "component_layouts"  # Change if your table name differs

    try:
        # Check if 'grid_number' column already exists
        result = conn.execute(
            text(f"SHOW COLUMNS FROM {table_name} LIKE 'grid_number';")
        ).fetchone()

        if result:
            print("⚠ Skipping 'grid_number' addition: column already exists.")
        else:
            conn.execute(
                text(f"ALTER TABLE {table_name} ADD COLUMN grid_number INT NOT NULL DEFAULT 0;")
            )
            print("✅ Added 'grid_number' column with default 0")

        # Ensure all rows have a grid_number set
        conn.execute(
            text(f"UPDATE {table_name} SET grid_number = 0 WHERE grid_number IS NULL;")
        )
        print("✅ Updated existing rows to have grid_number = 0")

    except SQLAlchemyError as e:
        print(f"Migration failed: {e}")

    finally:
        conn.close()
        print("✅ Completed migration: 014_add_grid_number_column_to_components_layout")

if __name__ == "__main__":
    run()
