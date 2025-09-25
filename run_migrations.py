import importlib
# List all migration scripts in order
MIGRATION_SCRIPTS = [
    "migrations.001_create_tables",
    "migrations.002_add_columns",
    "migrations.003_create_users_table",
    "migrations.004_add_user_password_columns",
    "migrations.005_create_panel_risk_table", 
    "migrations.006_ups_data_table_column"  
]
def run_migrations():
    for script in MIGRATION_SCRIPTS:
        print(f"🚀 Running {script}")
        module = importlib.import_module(script)
        module.run()
        print(f"✅ Completed {script}\n")

if __name__ == "__main__":
    run_migrations()
