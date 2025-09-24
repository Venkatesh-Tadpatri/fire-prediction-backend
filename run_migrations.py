import importlib
# List all migration scripts in order
MIGRATION_SCRIPTS = [
    "fire_prediction_backend.migrations.001_create_tables",
    "fire_prediction_backend.migrations.002_add_columns",
    "fire_prediction_backend.migrations.003_create_users_table",
    "fire_prediction_backend.migrations.004_add_user_password_columns",
    "fire_prediction_backend.migrations.005_create_panel_risk_table"   
]
def run_migrations():
    for script in MIGRATION_SCRIPTS:
        print(f"🚀 Running {script}")
        module = importlib.import_module(script)
        module.run()
        print(f"✅ Completed {script}\n")

if __name__ == "__main__":
    run_migrations()
