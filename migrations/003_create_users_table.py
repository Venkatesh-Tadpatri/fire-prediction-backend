from database import Base, engine
from models import User

def run():
    print("Creating users table...")
    Base.metadata.create_all(bind=engine, tables=[User.__table__])
    print("Users table created successfully!")
