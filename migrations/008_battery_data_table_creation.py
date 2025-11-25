from models import Base
from database import engine

def run():
    print("📦 Running migration: Create battery_live_data table")
    Base.metadata.create_all(bind=engine)
    print("✅ battery_live_data table created successfully")

if __name__ == "__main__":
    run()
