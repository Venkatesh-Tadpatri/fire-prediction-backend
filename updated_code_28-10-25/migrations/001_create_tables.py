from models import Base
from database import engine

def run():
    print("📦 Running migration: Create sensor_data table")
    Base.metadata.create_all(bind=engine)
    print("✅ sensor_data table created successfully")
