from models import Base
from database import engine

def run():
    print("📦 Running migration: Create switchboard table")
    Base.metadata.create_all(bind=engine)
    print("✅ switchboard table and columns created successfully")

if __name__ == "__main__":
    run()
