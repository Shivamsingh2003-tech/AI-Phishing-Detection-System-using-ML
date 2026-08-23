import sqlite3

conn = sqlite3.connect(
    "phishing.db"
)

cursor = conn.cursor()

cursor.execute(
"""
DELETE FROM scan_history
"""
)

conn.commit()

conn.close()

print(
"Database cleaned"
)