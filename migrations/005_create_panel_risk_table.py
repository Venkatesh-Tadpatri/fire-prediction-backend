from sqlalchemy import text
from models import Base, PanelRiskData
from database import engine

def run():
    print("📦 Running migration: Create panel_risk_data table")
    
    # Create the table if it doesn't exist
    Base.metadata.create_all(bind=engine, tables=[PanelRiskData.__table__])
    print("✅ panel_risk_data table created successfully")
    
    # Open a connection to check/add columns
    with engine.connect() as conn:
        # --- Check and add email ---
        result = conn.execute(text("SHOW COLUMNS FROM panel_risk_data LIKE 'email';"))
        if not result.first():
            conn.execute(text("ALTER TABLE panel_risk_data ADD COLUMN email VARCHAR(255) UNIQUE;"))
            print("✅ Added column: email")
        else:
            print("⚠ Column email already exists")
