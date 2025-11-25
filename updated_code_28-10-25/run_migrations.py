import importlib
# List all migration scripts in order
MIGRATION_SCRIPTS = [
    "migrations.001_create_tables",
    "migrations.002_add_columns",
    "migrations.003_create_users_table",
    "migrations.004_add_user_password_columns",
    "migrations.005_create_panel_risk_table", 
    "migrations.006_ups_data_table_column",
    "migrations.007_ac_data_table_creation",
    "migrations.008_battery_data_table_creation",
    "migrations.009_create_components_layout_table",
    "migrations.010_create_switchboard_data_table",
    "migrations.011_create_wiring_equipment_table_columns",
    # "migrations.012_update_wiring_equipment_columns",
    "migrations.013_create_floor_data_table"

]
def run_migrations():
    for script in MIGRATION_SCRIPTS:
        print(f"🚀 Running {script}")
        module = importlib.import_module(script)
        module.run()
        print(f"✅ Completed {script}\n")

if __name__ == "__main__":
    run_migrations()
