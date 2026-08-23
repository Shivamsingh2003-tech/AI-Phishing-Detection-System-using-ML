import sqlite3
import os
from datetime import datetime, timezone, timedelta

from werkzeug.security import generate_password_hash, check_password_hash


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "phishing.db")


# ============================================================
# INDIA TIME
# ============================================================

IST = timezone(timedelta(hours=5, minutes=30))


def current_ist_time():
    """Return current India date/time."""
    return datetime.now(IST).strftime("%Y-%m-%d %I:%M:%S %p")


# ============================================================
# DATABASE CONNECTION
# ============================================================

def connect():
    """
    Create SQLite database connection.
    """

    conn = sqlite3.connect(
        DB,
        timeout=10,
        check_same_thread=False
    )

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")

    return conn


# ============================================================
# SCAN HISTORY TABLE
# ============================================================

def create_table():
    """
    Create scan_history table if it does not exist.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                input_data TEXT,
                prediction TEXT,
                threat_score REAL DEFAULT 0,
                risk_level TEXT,
                scan_date TEXT NOT NULL
            )
        """)

        conn.commit()

        print("SCAN HISTORY TABLE READY")

    except Exception as e:
        print("CREATE SCAN TABLE ERROR:", e)

    finally:
        if conn:
            conn.close()


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    scan_type,
    input_data,
    prediction,
    threat_score,
    risk_level
):
    """
    Save URL / Email / Content / File scan result.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        scan_type = str(scan_type).strip().upper()
        input_data = str(input_data)
        prediction = str(prediction)
        risk_level = str(risk_level).strip().title()

        try:
            threat_score = float(threat_score)
        except (TypeError, ValueError):
            threat_score = 0.0

        # Keep score inside valid range
        threat_score = max(0.0, min(100.0, threat_score))

        scan_date = current_ist_time()

        cursor.execute("""
            INSERT INTO scan_history (
                scan_type,
                input_data,
                prediction,
                threat_score,
                risk_level,
                scan_date
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            scan_type,
            input_data,
            prediction,
            threat_score,
            risk_level,
            scan_date
        ))

        conn.commit()

        print("SCAN SAVED:", scan_date)

        return True

    except Exception as e:
        print("SAVE SCAN ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_history():
    """
    Return all scan records.
    Newest scan appears first.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                scan_type,
                input_data,
                prediction,
                threat_score,
                risk_level,
                scan_date
            FROM scan_history
            ORDER BY id DESC
        """)

        return cursor.fetchall()

    except Exception as e:
        print("GET HISTORY ERROR:", e)
        return []

    finally:
        if conn:
            conn.close()


# ============================================================
# UPDATE SCAN
# ============================================================

def update_scan(
    scan_id,
    prediction,
    threat_score,
    risk_level
):
    """
    Update an existing scan result.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        try:
            threat_score = float(threat_score)
        except (TypeError, ValueError):
            threat_score = 0.0

        threat_score = max(0.0, min(100.0, threat_score))

        cursor.execute("""
            UPDATE scan_history
            SET
                prediction = ?,
                threat_score = ?,
                risk_level = ?
            WHERE id = ?
        """, (
            str(prediction),
            threat_score,
            str(risk_level).strip().title(),
            int(scan_id)
        ))

        conn.commit()

        return cursor.rowcount > 0

    except Exception as e:
        print("UPDATE SCAN ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# DELETE SINGLE SCAN
# ============================================================

def delete_scan(scan_id):
    """
    Delete one scan by ID.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM scan_history
            WHERE id = ?
        """, (int(scan_id),))

        conn.commit()

        deleted = cursor.rowcount > 0

        if deleted:
            print("SCAN DELETED:", scan_id)

        return deleted

    except Exception as e:
        print("DELETE SCAN ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# CLEAR ALL SCAN HISTORY
# ============================================================

def clear_history():
    """
    Delete all scan history and reset ID sequence.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM scan_history")

        cursor.execute("""
            DELETE FROM sqlite_sequence
            WHERE name = ?
        """, ("scan_history",))

        conn.commit()

        print("SCAN HISTORY CLEARED")

        return True

    except Exception as e:
        print("CLEAR HISTORY ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# DASHBOARD / DEDUCTION REPORT
# ============================================================

def get_dashboard_stats():
    """
    Generate statistics for Deduction Report.
    """

    scans = get_history()

    stats = {
        "total_scans": 0,
        "total_url": 0,
        "total_email": 0,
        "total_content": 0,
        "total_file": 0,

        "high_risk": 0,
        "medium_risk": 0,
        "low_risk": 0,

        "phishing_count": 0,
        "suspicious_count": 0,
        "legitimate_count": 0,
        "unsafe_count": 0,
        "verified_count": 0,
        "error_count": 0
    }

    stats["total_scans"] = len(scans)

    for scan in scans:

        # Database structure:
        # 0 = id
        # 1 = scan_type
        # 2 = input_data
        # 3 = prediction
        # 4 = threat_score
        # 5 = risk_level
        # 6 = scan_date

        scan_type = str(scan[1]).strip().upper()
        prediction = str(scan[3]).strip().lower()
        risk_level = str(scan[5]).strip().lower()

        # ----------------------------
        # Scan type
        # ----------------------------

        if scan_type == "URL":
            stats["total_url"] += 1

        elif scan_type == "EMAIL":
            stats["total_email"] += 1

        elif scan_type == "CONTENT":
            stats["total_content"] += 1

        elif scan_type == "FILE":
            stats["total_file"] += 1

        # ----------------------------
        # Risk level
        # ----------------------------

        if risk_level == "high":
            stats["high_risk"] += 1

        elif risk_level == "medium":
            stats["medium_risk"] += 1

        elif risk_level == "low":
            stats["low_risk"] += 1

        # ----------------------------
        # Prediction
        # ----------------------------

        if "phishing" in prediction:
            stats["phishing_count"] += 1

        elif "suspicious" in prediction:
            stats["suspicious_count"] += 1

        elif (
            "legitimate" in prediction
            or "safe content" in prediction
        ):
            stats["legitimate_count"] += 1

        elif "unsafe" in prediction:
            stats["unsafe_count"] += 1

        elif "verified" in prediction:
            stats["verified_count"] += 1

        elif "error" in prediction:
            stats["error_count"] += 1

    return stats


# ============================================================
# ADMIN TABLE
# ============================================================

def create_admin_table():
    """
    Create admin table.

    Password is stored as a secure Werkzeug hash.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)

        conn.commit()

        print("ADMIN TABLE READY")

    except Exception as e:
        print("CREATE ADMIN TABLE ERROR:", e)

    finally:
        if conn:
            conn.close()


# ============================================================
# ADD ADMIN
# ============================================================

def add_admin(username, password):
    """
    Create a new administrator.

    Password is automatically hashed before storage.
    """

    conn = None

    try:
        username = str(username).strip()
        password = str(password)

        if not username or not password:
            print("USERNAME OR PASSWORD EMPTY")
            return False

        conn = connect()
        cursor = conn.cursor()

        password_hash = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO admin (
                username,
                password
            )
            VALUES (?, ?)
        """, (
            username,
            password_hash
        ))

        conn.commit()

        print("ADMIN CREATED:", username)

        return True

    except sqlite3.IntegrityError:
        print("ADMIN ALREADY EXISTS:", username)
        return False

    except Exception as e:
        print("ADD ADMIN ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# VALIDATE ADMIN LOGIN
# ============================================================

def validate_admin(username, password):
    """
    Validate administrator credentials.

    Supports:
    1. New hashed passwords
    2. Existing old plaintext passwords

    If an old plaintext password is successfully used,
    it is automatically converted to a secure hash.
    """

    conn = None

    try:
        username = str(username).strip()
        password = str(password)

        if not username or not password:
            return False

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username,
                password
            FROM admin
            WHERE username = ?
        """, (username,))

        row = cursor.fetchone()

        if not row:
            return False

        admin_id = row[0]
        stored_password = row[2]

        # ----------------------------------------
        # New hashed password
        # ----------------------------------------

        if stored_password.startswith(
            ("pbkdf2:", "scrypt:", "argon2:")
        ):
            return check_password_hash(
                stored_password,
                password
            )

        # ----------------------------------------
        # Old plaintext password migration
        # ----------------------------------------

        if stored_password == password:

            new_hash = generate_password_hash(password)

            cursor.execute("""
                UPDATE admin
                SET password = ?
                WHERE id = ?
            """, (
                new_hash,
                admin_id
            ))

            conn.commit()

            print(
                "OLD ADMIN PASSWORD MIGRATED:",
                username
            )

            return True

        return False

    except Exception as e:
        print("VALIDATE ADMIN ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# GET ALL ADMINS
# ============================================================

def get_admins():
    """
    Return admin ID and username only.
    Never expose password hashes.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username
            FROM admin
            ORDER BY id DESC
        """)

        return cursor.fetchall()

    except Exception as e:
        print("GET ADMINS ERROR:", e)
        return []

    finally:
        if conn:
            conn.close()


# ============================================================
# GET ADMIN BY ID
# ============================================================

def get_admin_by_id(admin_id):
    """
    Return admin ID and username.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username
            FROM admin
            WHERE id = ?
        """, (int(admin_id),))

        return cursor.fetchone()

    except Exception as e:
        print("GET ADMIN BY ID ERROR:", e)
        return None

    finally:
        if conn:
            conn.close()


# ============================================================
# GET ADMIN BY USERNAME
# ============================================================

def get_admin_by_username(username):
    """
    Return admin ID and username.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username
            FROM admin
            WHERE username = ?
        """, (str(username).strip(),))

        return cursor.fetchone()

    except Exception as e:
        print("GET ADMIN BY USERNAME ERROR:", e)
        return None

    finally:
        if conn:
            conn.close()


# ============================================================
# COUNT ADMINS
# ============================================================

def count_admins():
    """
    Return total number of administrators.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM admin
        """)

        row = cursor.fetchone()

        return row[0] if row else 0

    except Exception as e:
        print("COUNT ADMINS ERROR:", e)
        return 0

    finally:
        if conn:
            conn.close()


# ============================================================
# UPDATE ADMIN PASSWORD
# ============================================================

def update_admin_password(admin_id, new_password):
    """
    Change administrator password.

    Password is securely hashed before saving.
    """

    conn = None

    try:
        new_password = str(new_password)

        if not new_password.strip():
            return False

        conn = connect()
        cursor = conn.cursor()

        password_hash = generate_password_hash(
            new_password
        )

        cursor.execute("""
            UPDATE admin
            SET password = ?
            WHERE id = ?
        """, (
            password_hash,
            int(admin_id)
        ))

        conn.commit()

        return cursor.rowcount > 0

    except Exception as e:
        print("UPDATE ADMIN PASSWORD ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# DELETE ADMIN
# ============================================================

def delete_admin(admin_id):
    """
    Delete administrator by ID.

    Prevent deleting the final administrator.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM admin
        """)

        total_admins = cursor.fetchone()[0]

        if total_admins <= 1:
            print("CANNOT DELETE LAST ADMIN")
            return False

        cursor.execute("""
            DELETE FROM admin
            WHERE id = ?
        """, (int(admin_id),))

        conn.commit()

        return cursor.rowcount > 0

    except Exception as e:
        print("DELETE ADMIN ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# LOGIN HISTORY TABLE
# ============================================================

def create_login_history():
    """
    Create login history table.

    status:
        SUCCESS
        FAILED
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                status TEXT DEFAULT 'SUCCESS',
                login_time TEXT NOT NULL
            )
        """)

        conn.commit()

        # ----------------------------------------
        # Migration for older database
        # ----------------------------------------

        cursor.execute("""
            PRAGMA table_info(login_history)
        """)

        columns = [
            row[1]
            for row in cursor.fetchall()
        ]

        if "status" not in columns:

            cursor.execute("""
                ALTER TABLE login_history
                ADD COLUMN status TEXT DEFAULT 'SUCCESS'
            """)

            conn.commit()

            print("LOGIN HISTORY STATUS COLUMN ADDED")

        print("LOGIN HISTORY TABLE READY")

    except Exception as e:
        print("CREATE LOGIN HISTORY ERROR:", e)

    finally:
        if conn:
            conn.close()


# ============================================================
# SAVE LOGIN
# ============================================================

def save_login(username, status="SUCCESS"):
    """
    Save administrator login activity.

    Existing app.py can continue using:
        save_login(username)
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        username = str(username).strip()
        status = str(status).strip().upper()

        if status not in ("SUCCESS", "FAILED"):
            status = "SUCCESS"

        login_time = current_ist_time()

        cursor.execute("""
            INSERT INTO login_history (
                username,
                status,
                login_time
            )
            VALUES (?, ?, ?)
        """, (
            username,
            status,
            login_time
        ))

        conn.commit()

        print(
            "LOGIN SAVED:",
            username,
            status,
            login_time
        )

        return True

    except Exception as e:
        print("SAVE LOGIN ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# GET LOGIN HISTORY
# ============================================================

def get_login_history():
    """
    Return login history.

    Order:
        id
        username
        status
        login_time
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username,
                status,
                login_time
            FROM login_history
            ORDER BY id DESC
        """)

        return cursor.fetchall()

    except Exception as e:
        print("GET LOGIN HISTORY ERROR:", e)
        return []

    finally:
        if conn:
            conn.close()


# ============================================================
# CLEAR LOGIN HISTORY
# ============================================================

def clear_login_history():
    """
    Delete all login history and reset ID.
    """

    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM login_history
        """)

        cursor.execute("""
            DELETE FROM sqlite_sequence
            WHERE name = ?
        """, ("login_history",))

        conn.commit()

        print("LOGIN HISTORY CLEARED")

        return True

    except Exception as e:
        print("CLEAR LOGIN HISTORY ERROR:", e)
        return False

    finally:
        if conn:
            conn.close()


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_db():
    """
    Initialize all database tables.
    """

    create_table()
    create_admin_table()
    create_login_history()

    print("DATABASE INITIALIZATION COMPLETE")


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":
    init_db()