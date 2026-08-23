import sqlite3

conn = sqlite3.connect("phishing.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT,
    input_data TEXT,
    prediction TEXT,
    threat_score REAL,
    risk_level TEXT,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()

print("Database Created Successfully")