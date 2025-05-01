# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  Jaber Ali Farooqi · W1926781 · University of Westminster                ║
# ║  Final-Year Project – ThreatDetect (Real-Time Network Threat Detection)  ║
# ║  © 2025                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════╝
"""
Database helpers for ThreatDetect
=================================

A very small SQLite‐backed module that stores:

* **users**          – registration / login credentials
* **sniffed_data**   – every flow predicted by the real-time sniffer

Design notes
------------
* Uses *one* on-disk file at `./database/db.db`.  
  (`createDabase()` makes sure parent dir + tables exist.)
* All write helpers open a **new** connection, commit, then close –– fine
  for low-volume usage but you might switch to a pooled engine later.
* Every public function is documented; internal helper names are
  intentionally “private” (prefixed with `_` if added later).

Security caveats
----------------
* Passwords are already hashed by the caller (see auth layer), so we do
  **not** hash again here.
* No SQL injection risk because every query uses `?` parameter bindings,
  but watch out if you add dynamic `ORDER BY` or `LIMIT` clauses.

Typos / placeholders
--------------------
* The function `createDabase` is spelled as in the original source
  (missing the second “a”) – left untouched for consistency.
* In `fetch_sniffed_data_overview` you’ll see tuples like  
  `("BOT", "DDOS", "PORTSCAN", "DOS HULK", ...)`.  
  The literal `...` will raise a `SyntaxError` if executed.  
  Replace it with actual label strings or remove the ellipsis in
  production.
"""

# ---------------------------------------------------------------------------  
# Standard-library imports  
# ---------------------------------------------------------------------------
import os
import json
import sqlite3
from collections import defaultdict
from datetime import datetime

# =============================================================================
# ---------------------------  INITIALISATION  --------------------------------
# =============================================================================
def createDabase() -> None:     # ← kept misspelling for backward-compat
    """
    Ensure the SQLite file exists **and** both required tables are created.
    Called once on module import.
    """
    global conn, cursor         # Only used by this bootstrap step
    cwd = os.getcwd()
    db_path = os.path.join(cwd, "database", "db.db")

    # `check_same_thread=False` lets us share the connection across threads.
    conn   = sqlite3.connect(db_path, check_same_thread=False)
    cursor = conn.cursor()

    # ----------------------- create `users` table ------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email    TEXT UNIQUE,
            password TEXT,
            mobile   TEXT
        )
    """)

    # ---------------------- create `sniffed_data` table ------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sniffed_data (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_key         TEXT,
            features_json    TEXT,
            prediction_label TEXT,
            timestamp        REAL
        )
    """)

    conn.commit()
    print("Database Initialised / Created")

# =============================================================================
# ---------------------------  CONNECTION HELPER  -----------------------------
# =============================================================================
def get_connection() -> sqlite3.Connection:
    """
    Return a *fresh* connection to the same SQLite file.

    Keeping connections short-lived avoids ‘database is locked’ errors
    under multi-threaded load.
    """
    db_path = os.path.join(os.getcwd(), "database", "db.db")
    return sqlite3.connect(db_path, check_same_thread=False)

# =============================================================================
# ---------------------------  USER FUNCTIONS  --------------------------------
# =============================================================================
def InsertData(name: str, email: str, hashed_password: str, mobile) -> None:
    """
    Insert a new user row (password is already **hashed** by caller).
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO users (username, email, password, mobile)
        VALUES (?, ?, ?, ?)
    """, (name, email, hashed_password, str(mobile)))
    conn.commit()
    conn.close()
    print("Inserted Data into users")

def read_cred(email: str):
    """
    Fetch `(username, email, password, mobile)` for login verification.

    Returns `None` if the e-mail address is not registered.
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT username, email, password, mobile
        FROM   users
        WHERE  email = ?
    """, (email,))
    row = cur.fetchone()
    conn.close()
    return row  # → None if not found

# =============================================================================
# ---------------------------  SNIFFED FLOW LOGGING  --------------------------
# =============================================================================
def insert_sniffed_flow(flow_key: str,
                        features: dict,
                        prediction_label: str,
                        timestamp: float) -> None:
    """
    Persist one flow’s computed features + prediction result.

    * `features` is a *raw* Python dict → stored as JSON string so that the
      table schema stays fixed even if feature set evolves.
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        INSERT INTO sniffed_data (flow_key, features_json, prediction_label, timestamp)
        VALUES (?, ?, ?, ?)
    """, (flow_key, json.dumps(features), prediction_label, timestamp))
    conn.commit()
    conn.close()

# =============================================================================
# ---------------------------  FETCHING HELPERS  ------------------------------
# =============================================================================
def get_sniffed_data():
    """
    Return **all** rows from `sniffed_data` as a list of dicts ready for JSON.
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, flow_key, features_json, prediction_label, timestamp
        FROM   sniffed_data
    """)
    rows = cur.fetchall()
    conn.close()

    return [{
        "id":               r[0],
        "flow_key":         r[1],
        "features":         r[2],   # still JSON string (caller may decode)
        "prediction_label": r[3],
        "timestamp":        r[4]
    } for r in rows]

def get_label_counts():
    """
    Aggregate number of flows per `prediction_label` for pie-charts & stats.
    """
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("""
        SELECT prediction_label, COUNT(*)
        FROM   sniffed_data
        GROUP  BY prediction_label
    """)
    rows = cur.fetchall()
    conn.close()

    return {label: count for label, count in rows}

# =============================================================================
# ---------------------------  DASHBOARD OVERVIEW  ----------------------------
# =============================================================================
def fetch_sniffed_data_overview():
    """
    Build three lightweight artefacts for the front-end dashboard:

    * **records**    – list of flows (limited set of columns)
    * **donutChart** – benign / malicious / other counts
    * **lineChart**  – daily trend of the same three categories
    """
    conn = get_connection()
    cur  = conn.cursor()

    # ---- Determine which columns actually exist (future-proofing) -------
    cur.execute("PRAGMA table_info(sniffed_data)")
    existing_cols = [row[1] for row in cur.fetchall()]

    desired = ["id", "flow_key", "prediction_label", "timestamp", "features_json"]
    selected_cols = [c for c in desired if c in existing_cols]

    if not selected_cols:          # table empty or mis-matched schema
        conn.close()
        return {
            "records":    [],
            "donutChart": {"malicious": 0, "safe": 0, "other": 0},
            "lineChart":  []
        }

    # ------------------------ Fetch rows ----------------------------------
    cur.execute(f"SELECT {', '.join(selected_cols)} FROM sniffed_data")
    rows = cur.fetchall()
    conn.close()

    # Convert → list[dict]
    records = [
        {col: row[i] for i, col in enumerate(selected_cols)}
        for row in rows
    ]

    # ------------------------ Donut counts --------------------------------
    benign   = malicious = other = 0

    for r in records:
        label = (r.get("prediction_label") or "").upper()
        if label == "BENIGN":
            benign += 1
        elif label in ("BOT", "DDOS", "PORTSCAN", "DOS HULK",
                       "FTP-PATATOR", ...):   # ← placeholder “...”
            malicious += 1
        else:
            other += 1

    donut_data = {"malicious": malicious, "safe": benign, "other": other}

    # ------------------------ Line-chart data -----------------------------
    stats_by_date = defaultdict(lambda: {"safe": 0, "malicious": 0, "other": 0})

    for r in records:
        ts = r.get("timestamp")
        if not ts:
            continue

        date_str = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        label    = (r.get("prediction_label") or "").upper()

        if label == "BENIGN":
            stats_by_date[date_str]["safe"] += 1
        elif label in ("BOT", "DDOS", "DOS HULK", ...):    # ← placeholder
            stats_by_date[date_str]["malicious"] += 1
        else:
            stats_by_date[date_str]["other"] += 1

    line_chart = [
        {
            "date":       d,
            "safe":       stats["safe"],
            "malicious":  stats["malicious"],
            "other":      stats["other"]
        }
        for d, stats in sorted(stats_by_date.items())       # chronological
    ]

    return {
        "records":    records,
        "donutChart": donut_data,
        "lineChart":  line_chart
    }

# =============================================================================
# ---------------------------  MODULE BOOTSTRAP  ------------------------------
# =============================================================================
# Run table creation immediately when the module is imported.
createDabase()
