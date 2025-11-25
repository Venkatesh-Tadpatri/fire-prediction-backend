# from sqlalchemy import create_engine, text
# from sqlalchemy.exc import ProgrammingError
# import os
# from dotenv import load_dotenv

# def run():
#     print("Running migrations.013_add_user_role_columns")

#     load_dotenv()
#     mysql_url = os.getenv("MYSQL_URL")

#     engine = create_engine(mysql_url)
#     conn = engine.connect()
#     table_name = "users"  # change if your table name is different

#     #Add 'role' column
#     try:
#         conn.execute(
#             text(f"ALTER TABLE {table_name} ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'user';")
#         )
#         print("Added 'role' column")
#     except ProgrammingError as e:
#         print(f"⚠ Skipping 'role' addition: {e}")

#     #Add 'assigned_admin' column
#     try:
#         conn.execute(
#             text(f"ALTER TABLE {table_name} ADD COLUMN assigned_admin VARCHAR(50) NOT NULL DEFAULT 'none';")
#         )
#         print("Added 'assigned_admin' column")
#     except ProgrammingError as e:
#         print(f"⚠ Skipping 'assigned_admin' addition: {e}")

#     conn.close()
#     print("Completed migrations.013_add_user_role_columns")



from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv

def run():
    print("📦 Running migration: 013_add_user_role_columns")

    load_dotenv()
    mysql_url = os.getenv("MYSQL_URL")

    engine = create_engine(mysql_url)
    conn = engine.connect()
    table_name = "users"

    # Helper function to check if a column exists
    def column_exists(column_name):
        result = conn.execute(
            text(f"SHOW COLUMNS FROM {table_name} LIKE '{column_name}';")
        )
        return result.fetchone() is not None

    # ✅ Add 'role' column safely
    if not column_exists("role"):
        conn.execute(
            text(f"ALTER TABLE {table_name} ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'user';")
        )
        print("✅ Added 'role' column (default='user')")
    else:
        print("⚠ 'role' column already exists — skipping addition")

    # ✅ Add 'assigned_admin' column safely
    if not column_exists("assigned_admin"):
        conn.execute(
            text(f"ALTER TABLE {table_name} ADD COLUMN assigned_admin VARCHAR(50) NOT NULL DEFAULT 'none';")
        )
        print("✅ Added 'assigned_admin' column (default='none')")
    else:
        print("⚠ 'assigned_admin' column already exists — skipping addition")

    conn.close()
    print("✅ Completed migration: 013_add_user_role_columns")

if __name__ == "__main__":
    run()
