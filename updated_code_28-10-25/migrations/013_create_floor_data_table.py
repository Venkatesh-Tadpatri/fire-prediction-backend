from models import Base
from database import engine

def run():
    print("📦 Running migration: Create floor_data table")
    Base.metadata.create_all(bind=engine)
    print("✅ floor_data table created successfully")


