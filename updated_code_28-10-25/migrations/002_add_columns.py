from sqlalchemy import MetaData, Table, text
from database import engine

def run():
    print("🔧 Running migration: Add voltage, air_velocity, and pressure columns")

    metadata = MetaData()
    metadata.reflect(bind=engine)

    sensor_data = metadata.tables.get("sensor_data")

    if sensor_data is None:
        return

    with engine.connect() as conn:
        existing_columns = sensor_data.columns.keys()

        if 'voltage' not in existing_columns:
            conn.execute(text('ALTER TABLE sensor_data ADD COLUMN voltage FLOAT'))

        if 'air_velocity' not in existing_columns:
            conn.execute(text('ALTER TABLE sensor_data ADD COLUMN air_velocity FLOAT'))
            
        if 'pressure' not in existing_columns:
            conn.execute(text('ALTER TABLE sensor_data ADD COLUMN pressure FLOAT'))
           

    print("Migration completed successfully")
