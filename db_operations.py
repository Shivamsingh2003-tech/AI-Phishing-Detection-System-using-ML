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
    """Create SQLite database connection."""
    conn = sqlite3.connect(
        DB,
        timeout=30,
        check_same_thread=False
    )

    conn.execute("PRAGMA foreign_keys = ON")

    return conn


# ============================================================
# SCAN HISTORY TABLE
# ============================================================

def create_table():
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

        threat_score = max(
            0.0,
            min(100.0, threat_score)
        )

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
    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        try:
            threat_score = float(threat_score)
        except (TypeError, ValueError):
            threat_score = 0.0

        threat_score = max(
            0.0,
            min(100.0, threat_score)
        )

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
    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM scan_history
            WHERE id = ?
        """, (int(scan_id),))

        conn.commit()

        return cursor.rowcount > 0

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
    conn = None

    try:
        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM scan_history
        """)

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
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_stats():

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

        scan_type = str(scan[1]).strip().upper()
        prediction = str(scan[3]).strip().lower()
        risk_level = str(scan[5]).strip().lower()

        # ----------------------------------------------------
        # SCAN TYPE
        # ----------------------------------------------------

        if scan_type == "URL":
            stats["total_url"] += 1

        elif scan_type == "EMAIL":
            stats["total_email"] += 1

        elif scan_type == "CONTENT":
            stats["total_content"] += 1

        elif scan_type == "FILE":
            stats["total_file"] += 1

        # ----------------------------------------------------
        # RISK LEVEL
        # ----------------------------------------------------

        if risk_level == "high":
            stats["high_risk"] += 1

        elif risk_level == "medium":
            stats["medium_risk"] += 1

        elif risk_level == "low":
            stats["low_risk"] += 1

        # ----------------------------------------------------
        # PREDICTION
        # ----------------------------------------------------

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
# PASSWORD HASH HELPER
# ============================================================

def _is_password_hash(value):
    """
    Return True when the stored value looks
    like a Werkzeug password hash.
    """

    if not value:
        return False

    value = str(value)

    return value.startswith(
        (
            "pbkdf2:",
            "scrypt:",
            "argon2:"
        )
    )


# ============================================================
# ADD ADMIN
# ============================================================

def add_admin(username, password):

    conn = None

    try:

        username = str(username).strip()
        password = str(password)

        if not username or not password:
            print("USERNAME OR PASSWORD EMPTY")
            return False

        conn = connect()
        cursor = conn.cursor()

        password_hash = generate_password_hash(
            password
        )

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

        print(
            "ADMIN CREATED:",
            username
        )

        return True

    except sqlite3.IntegrityError:

        print(
            "ADMIN ALREADY EXISTS:",
            username
        )

        return False

    except Exception as e:

        print("ADD ADMIN ERROR:", e)

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# ENSURE DEFAULT ADMIN
# ============================================================

def ensure_default_admin():
    """
    Creates the default admin only when no admin exists.

    Environment variables:

        ADMIN_USERNAME=admin
        ADMIN_PASSWORD=<your password>

    To deliberately replace an existing admin password once:

        FORCE_ADMIN_PASSWORD_RESET=true

    After successful deployment/login:

        FORCE_ADMIN_PASSWORD_RESET=false
    """

    username = os.getenv(
        "ADMIN_USERNAME",
        "admin"
    ).strip()

    password = os.getenv(
        "ADMIN_PASSWORD",
        ""
    )

    force_reset = os.getenv(
        "FORCE_ADMIN_PASSWORD_RESET",
        "false"
    ).strip().lower() == "true"

    if not username:

        print(
            "DEFAULT ADMIN ERROR: "
            "ADMIN_USERNAME IS EMPTY"
        )

        return False

    conn = None

    try:

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username,
                password
            FROM admin
            ORDER BY id ASC
        """)

        admins = cursor.fetchall()

        # ----------------------------------------------------
        # NO ADMIN EXISTS
        # ----------------------------------------------------

        if not admins:

            if not password:

                print(
                    "DEFAULT ADMIN NOT CREATED: "
                    "ADMIN_PASSWORD ENVIRONMENT VARIABLE "
                    "IS MISSING"
                )

                return False

            password_hash = generate_password_hash(
                password
            )

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

            print(
                "DEFAULT ADMIN CREATED:",
                username
            )

            return True

        # ----------------------------------------------------
        # FORCE PASSWORD RESET
        # ----------------------------------------------------

        if force_reset:

            if not password:

                print(
                    "FORCE PASSWORD RESET REQUESTED "
                    "BUT ADMIN_PASSWORD IS EMPTY"
                )

                return False

            cursor.execute("""
                SELECT id
                FROM admin
                WHERE username = ?
            """, (username,))

            row = cursor.fetchone()

            if row:

                password_hash = generate_password_hash(
                    password
                )

                cursor.execute("""
                    UPDATE admin
                    SET password = ?
                    WHERE id = ?
                """, (
                    password_hash,
                    row[0]
                ))

                conn.commit()

                print(
                    "ADMIN PASSWORD FORCE-RESET "
                    "SUCCESSFULLY:",
                    username
                )

                return True

            print(
                "FORCE PASSWORD RESET FAILED: "
                "ADMIN USERNAME NOT FOUND:",
                username
            )

            return False

        # ----------------------------------------------------
        # ADMIN ALREADY EXISTS
        # ----------------------------------------------------

        print(
            "ADMIN ALREADY EXISTS:",
            username
        )

        return True

    except Exception as e:

        if conn:
            conn.rollback()

        print(
            "ENSURE DEFAULT ADMIN ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# GET ADMIN BY USERNAME
# ============================================================

def get_admin_by_username(username):

    conn = None

    try:

        username = str(username).strip()

        if not username:
            return None

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

        return cursor.fetchone()

    except Exception as e:

        print(
            "GET ADMIN BY USERNAME ERROR:",
            e
        )

        return None

    finally:

        if conn:
            conn.close()


# ============================================================
# GET ADMIN BY ID
# ============================================================

def get_admin_by_id(admin_id):

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

        print(
            "GET ADMIN BY ID ERROR:",
            e
        )

        return None

    finally:

        if conn:
            conn.close()


# ============================================================
# VALIDATE ADMIN LOGIN
# ============================================================

def validate_admin(username, password):

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

            print(
                "ADMIN NOT FOUND:",
                username
            )

            return False

        admin_id = row[0]
        stored_password = str(row[2])

        # ----------------------------------------------------
        # SECURE HASHED PASSWORD
        # ----------------------------------------------------

        if _is_password_hash(
            stored_password
        ):

            return check_password_hash(
                stored_password,
                password
            )

        # ----------------------------------------------------
        # LEGACY PLAINTEXT PASSWORD
        # ----------------------------------------------------

        if stored_password == password:

            new_hash = generate_password_hash(
                password
            )

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
                "OLD PASSWORD CONVERTED TO HASH:",
                username
            )

            return True

        return False

    except Exception as e:

        print(
            "VALIDATE ADMIN ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# UPDATE PASSWORD BY ADMIN ID
# ============================================================

def update_admin_password(
    admin_id,
    new_password
):

    conn = None

    try:

        new_password = str(new_password)

        if len(new_password) < 8:

            print(
                "PASSWORD MUST CONTAIN "
                "AT LEAST 8 CHARACTERS"
            )

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

        updated = cursor.rowcount

        conn.commit()

        if updated == 1:

            print(
                "ADMIN PASSWORD UPDATED:",
                admin_id
            )

            return True

        print(
            "ADMIN PASSWORD UPDATE FAILED - "
            "ADMIN NOT FOUND:",
            admin_id
        )

        return False

    except Exception as e:

        if conn:
            conn.rollback()

        print(
            "UPDATE ADMIN PASSWORD ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# RESET PASSWORD BY USERNAME
# ============================================================

def reset_admin_password(
    username,
    new_password
):
    """
    Reset administrator password using username.

    The new password is always stored
    as a secure Werkzeug hash.
    """

    conn = None

    try:

        username = str(username).strip()
        new_password = str(new_password)

        if not username:

            print(
                "RESET PASSWORD ERROR: "
                "USERNAME EMPTY"
            )

            return False

        if not new_password:

            print(
                "RESET PASSWORD ERROR: "
                "PASSWORD EMPTY"
            )

            return False

        if len(new_password) < 8:

            print(
                "RESET PASSWORD ERROR: "
                "PASSWORD MUST BE AT LEAST "
                "8 CHARACTERS"
            )

            return False

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username
            FROM admin
            WHERE username = ?
        """, (username,))

        admin = cursor.fetchone()

        if not admin:

            print(
                "RESET PASSWORD ERROR: "
                "ADMIN NOT FOUND:",
                username
            )

            return False

        admin_id = admin[0]

        # ----------------------------------------------------
        # CREATE NEW PASSWORD HASH
        # ----------------------------------------------------

        new_password_hash = generate_password_hash(
            new_password
        )

        cursor.execute("""
            UPDATE admin
            SET password = ?
            WHERE id = ?
        """, (
            new_password_hash,
            admin_id
        ))

        if cursor.rowcount != 1:

            conn.rollback()

            print(
                "RESET PASSWORD ERROR: "
                "PASSWORD WAS NOT UPDATED"
            )

            return False

        conn.commit()

        # ----------------------------------------------------
        # IMMEDIATE VERIFICATION
        # ----------------------------------------------------

        cursor.execute("""
            SELECT password
            FROM admin
            WHERE id = ?
        """, (admin_id,))

        updated_row = cursor.fetchone()

        if not updated_row:

            print(
                "RESET PASSWORD ERROR: "
                "COULD NOT VERIFY "
                "UPDATED PASSWORD"
            )

            return False

        if not check_password_hash(
            updated_row[0],
            new_password
        ):

            print(
                "RESET PASSWORD ERROR: "
                "PASSWORD VERIFICATION FAILED"
            )

            return False

        print(
            "ADMIN PASSWORD RESET SUCCESSFULLY:",
            username
        )

        return True

    except Exception as e:

        if conn:
            conn.rollback()

        print(
            "RESET ADMIN PASSWORD ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# COMPATIBILITY ALIAS
# ============================================================

# app.py currently expects:
#
#     reset_admin_password_db
#
# The actual database function is:
#
#     reset_admin_password
#
# This alias allows both names to work.

reset_admin_password_db = reset_admin_password


# ============================================================
# CHANGE PASSWORD USING CURRENT PASSWORD
# ============================================================

def change_admin_password(
    username,
    current_password,
    new_password
):

    conn = None

    try:

        username = str(username).strip()
        current_password = str(current_password)
        new_password = str(new_password)

        if not username:
            return False

        if len(new_password) < 8:
            return False

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                password
            FROM admin
            WHERE username = ?
        """, (username,))

        row = cursor.fetchone()

        if not row:
            return False

        admin_id = row[0]
        stored_password = str(row[1])

        # ----------------------------------------------------
        # CHECK CURRENT PASSWORD
        # ----------------------------------------------------

        if _is_password_hash(
            stored_password
        ):

            valid = check_password_hash(
                stored_password,
                current_password
            )

        else:

            valid = (
                stored_password
                == current_password
            )

        if not valid:
            return False

        # ----------------------------------------------------
        # SAVE NEW PASSWORD
        # ----------------------------------------------------

        new_hash = generate_password_hash(
            new_password
        )

        cursor.execute("""
            UPDATE admin
            SET password = ?
            WHERE id = ?
        """, (
            new_hash,
            admin_id
        ))

        conn.commit()

        return cursor.rowcount == 1

    except Exception as e:

        if conn:
            conn.rollback()

        print(
            "CHANGE ADMIN PASSWORD ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# GET ALL ADMINS
# ============================================================

def get_admins():

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

        print(
            "GET ADMINS ERROR:",
            e
        )

        return []

    finally:

        if conn:
            conn.close()


# ============================================================
# COUNT ADMINS
# ============================================================

def count_admins():

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

        print(
            "COUNT ADMINS ERROR:",
            e
        )

        return 0

    finally:

        if conn:
            conn.close()


# ============================================================
# DELETE ADMIN
# ============================================================

def delete_admin(admin_id):

    conn = None

    try:

        conn = connect()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM admin
        """)

        total_admins = cursor.fetchone()[0]

        # Never delete the last admin.
        if total_admins <= 1:

            print(
                "CANNOT DELETE LAST ADMIN"
            )

            return False

        cursor.execute("""
            DELETE FROM admin
            WHERE id = ?
        """, (int(admin_id),))

        conn.commit()

        return cursor.rowcount > 0

    except Exception as e:

        if conn:
            conn.rollback()

        print(
            "DELETE ADMIN ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# LOGIN HISTORY TABLE
# ============================================================

def create_login_history():

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

        # ----------------------------------------------------
        # CHECK FOR STATUS COLUMN
        # ----------------------------------------------------

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

            print(
                "LOGIN HISTORY STATUS COLUMN ADDED"
            )

        print(
            "LOGIN HISTORY TABLE READY"
        )

    except Exception as e:

        print(
            "CREATE LOGIN HISTORY ERROR:",
            e
        )

    finally:

        if conn:
            conn.close()


# ============================================================
# SAVE LOGIN
# ============================================================

def save_login(
    username,
    status="SUCCESS"
):

    conn = None

    try:

        conn = connect()
        cursor = conn.cursor()

        username = str(username).strip()
        status = str(status).strip().upper()

        if status not in (
            "SUCCESS",
            "FAILED"
        ):

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

        return True

    except Exception as e:

        print(
            "SAVE LOGIN ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# GET LOGIN HISTORY
# ============================================================

def get_login_history():

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

        print(
            "GET LOGIN HISTORY ERROR:",
            e
        )

        return []

    finally:

        if conn:
            conn.close()


# ============================================================
# CLEAR LOGIN HISTORY
# ============================================================

def clear_login_history():

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

        print(
            "LOGIN HISTORY CLEARED"
        )

        return True

    except Exception as e:

        print(
            "CLEAR LOGIN HISTORY ERROR:",
            e
        )

        return False

    finally:

        if conn:
            conn.close()


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    print(
        "========================================"
    )

    print(
        "INITIALIZING DATABASE"
    )

    print(
        "DATABASE:",
        DB
    )

    print(
        "========================================"
    )

    create_table()
    create_admin_table()
    create_login_history()

    # Create the admin from environment variables
    # only when necessary, or perform an explicit
    # one-time password reset when:
    #
    # FORCE_ADMIN_PASSWORD_RESET=true

    ensure_default_admin()

    print(
        "DATABASE INITIALIZATION COMPLETE"
    )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":
    init_db()