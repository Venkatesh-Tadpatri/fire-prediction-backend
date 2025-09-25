from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

# Load .env from the project root
dotenv_path = os.path.join(os.path.dirname(__file__), ".env")
print("Looking for .env at:", dotenv_path)
load_dotenv(dotenv_path)

MYSQL_URL = os.getenv("MYSQL_URL")
print("Loaded MYSQL_URL:", MYSQL_URL)

if not MYSQL_URL:
    raise ValueError("MYSQL_URL is not set. Check your .env file!")

# Database engine
engine = create_engine(MYSQL_URL)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ✅ Base class for models (this was missing!)
Base = declarative_base()

# Export cleanly
__all__ = ["engine", "SessionLocal", "Base"]

