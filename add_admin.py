import os
import sys
import psycopg2
from getpass import getpass
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "internet_shop_bd")
DB_USER = os.environ.get("DB_USER", "myshop_user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "1234")

try:
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE username = %s", ('admin',))
    admin = cur.fetchone()

    if admin:
        print("Пользователь с именем 'admin' уже существует (ID: {}).".format(admin[0]))
        sys.exit(0)

    print("Создание новой учетной записи администратора.")
    admin_password = getpass("Введите пароль для администратора: ")
    admin_email = input("Введите email для администратора (например, admin@example.com): ").strip()

    cur.execute("""
        INSERT INTO users (username, email, password_hash, is_admin)
        VALUES (%s, %s, %s, %s)
        RETURNING id;
    """, ("admin", admin_email, admin_password, True))

    admin_id = cur.fetchone()[0]
    conn.commit()
    print("Учетная запись администратора успешно создана! ID нового администратора:", admin_id)

except Exception as e:
    print("Ошибка при работе с базой данных:", e)
    sys.exit(1)

finally:
    if 'cur' in locals():
        cur.close()
    if 'conn' in locals():
        conn.close()
