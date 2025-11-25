from models import Base
from database import engine

def run():
    print("📦 Running migration: Create components layout table")
    Base.metadata.create_all(bind=engine)
    print("✅ components layout table created successfully")

if __name__ == "__main__":
    run()
