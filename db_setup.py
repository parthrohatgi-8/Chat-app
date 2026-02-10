import mysql.connector

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root"
)
cursor = conn.cursor()

cursor.execute("CREATE DATABASE IF NOT EXISTS chat_app")
conn.database = "chat_app"

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    unique_id INT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

print("✅ Database & users table ready")

cursor.close()
conn.close()
