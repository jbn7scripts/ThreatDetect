# Database.py
import sqlite3
import os
import json

def createDabase():
    """
    Create DB connection and ensure the tables exist.
    """
    global conn, cursor
    cwd = os.getcwd()
    database_path = os.path.join(cwd, 'database', 'db.db')
    conn = sqlite3.connect(database_path, check_same_thread=False)
    cursor = conn.cursor()
    
    # Create 'users' table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT UNIQUE,
            password TEXT,
            mobile TEXT
        )
    """)
    
    # Create table for sniffed flows
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sniffed_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_key TEXT,
            features_json TEXT,
            prediction_label TEXT,
            timestamp REAL
        )
    """)
    
    conn.commit()
    print('Database Initialized/Created')

def get_connection():
    """
    Utility to get a connection for queries.
    """
    cwd = os.getcwd()
    database_path = os.path.join(cwd, 'database', 'db.db')
    conn = sqlite3.connect(database_path, check_same_thread=False)
    return conn

def InsertData(name, email, hashed_password, mobile):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, email, password, mobile)
        VALUES (?, ?, ?, ?)
    """, (name, email, hashed_password, str(mobile)))
    conn.commit()
    conn.close()
    print('Inserted Data into users')

def read_cred(email):
    """
    Return user row for the given email (username, email, password, mobile).
    We'll do password check in code, not in SQL.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, email, password, mobile
        FROM users
        WHERE email=?
    """, (email,))
    fetch = cursor.fetchone()
    conn.close()
    return fetch  # can be None if not found

def insert_sniffed_flow(flow_key, features, prediction_label, timestamp):
    conn = get_connection()
    cursor = conn.cursor()
    features_json = json.dumps(features)
    cursor.execute("""
        INSERT INTO sniffed_data (flow_key, features_json, prediction_label, timestamp)
        VALUES (?, ?, ?, ?)
    """, (flow_key, features_json, prediction_label, timestamp))
    conn.commit()
    conn.close()

def get_sniffed_data():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, flow_key, features_json, prediction_label, timestamp FROM sniffed_data")
    rows = cursor.fetchall()
    conn.close()

    data = []
    for row in rows:
        data.append({
            "id": row[0],
            "flow_key": row[1],
            "features": row[2],  # JSON string
            "prediction_label": row[3],
            "timestamp": row[4]
        })
    return data

def get_label_counts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT prediction_label, COUNT(*)
        FROM sniffed_data
        GROUP BY prediction_label
    """)
    rows = cursor.fetchall()
    conn.close()

    label_counts = {}
    for label, count in rows:
        label_counts[label] = count
    return label_counts

def fetch_sniffed_data_overview():
    """
    Use 'sniffed_data' table to build:
      - "records": a list of sniffed flows
      - "donutChart": counts of 'BENIGN' vs. 'malicious' vs. 'other'
      - "lineChart": grouping flows by date from 'timestamp'
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Check columns in 'sniffed_data'
    cursor.execute("PRAGMA table_info(sniffed_data)")
    table_info = cursor.fetchall()
    existing_cols = [row[1] for row in table_info]

    # We'll "desire" certain columns
    desired_cols = ["id", "flow_key", "prediction_label", "timestamp", "features_json"]
    # Intersect with what's actually in the table
    selected_cols = [c for c in desired_cols if c in existing_cols]
    if not selected_cols:
        conn.close()
        return {
            "records": [],
            "donutChart": {"malicious": 0, "safe": 0, "other": 0},
            "lineChart": []
        }

    col_string = ", ".join(selected_cols)
    query = f"SELECT {col_string} FROM sniffed_data"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    # Convert to list of dict
    records = []
    for row in rows:
        row_dict = {}
        for i, col_name in enumerate(selected_cols):
            row_dict[col_name] = row[i]
        records.append(row_dict)

    # Donut chart logic
    benign_count = 0
    malicious_count = 0
    other_count = 0

    for r in records:
        plabel = (r.get("prediction_label") or "").upper()
        if plabel == "BENIGN":
            benign_count += 1
        elif plabel in ("BOT", "DDOS", "PORTSCAN", "DOS HULK", "FTP-PATATOR", ...):
            # or you can just do: if plabel != "BENIGN", treat as malicious
            malicious_count += 1
        else:
            other_count += 1

    donut_data = {
        "malicious": malicious_count,
        "safe": benign_count,
        "other": other_count
    }

    # Build line chart grouping by date from 'timestamp'
    from collections import defaultdict
    from datetime import datetime
    stats_by_date = defaultdict(lambda: {"safe": 0, "malicious": 0, "other": 0})

    for r in records:
        ts = r.get("timestamp")
        if not ts:
            continue
        # Convert float to date: e.g. 1681250400 -> 2025-04-10
        # This is naive if your timestamps aren't standard Unix epochs, but let's assume.
        date_str = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")

        plabel = (r.get("prediction_label") or "").upper()
        if plabel == "BENIGN":
            stats_by_date[date_str]["safe"] += 1
        else:
            # treat everything else as malicious, or if you want some logic for "other"
            # but for example:
            if plabel in ("BOT", "DDOS", "DOS HULK", ...):
                stats_by_date[date_str]["malicious"] += 1
            else:
                stats_by_date[date_str]["other"] += 1

    line_chart = []
    for d in sorted(stats_by_date.keys()):
        line_chart.append({
            "date": d,
            "safe": stats_by_date[d]["safe"],
            "malicious": stats_by_date[d]["malicious"],
            "other": stats_by_date[d]["other"]
        })

    return {
        "records": records,
        "donutChart": donut_data,
        "lineChart": line_chart
    }

def fetch_dashboard_overview():
    """
    Returns all data needed for the dashboard: records, donut, line, KPIs, recent alerts, top malicious IPs.
    """
    # Reuse your existing logic from fetch_sniffed_data_overview
    overview = fetch_sniffed_data_overview()
    records = overview["records"]
    donut_data = overview["donutChart"]
    line_chart = overview["lineChart"]

    # KPIs
    total_records = len(records)
    malicious_count = donut_data['malicious']
    safe_count = donut_data['safe']
    detection_accuracy = round(100 * safe_count / total_records, 2) if total_records else 0

    # Recent alerts (last 10 malicious)
    recent_alerts = [
        {
            "time": r["timestamp"],
            "type": r["prediction_label"],
            "source": r["flow_key"].split(',')[1].replace("'", '').strip() if ',' in r["flow_key"] else '',
            "destination": r["flow_key"].split(',')[0].replace('(', '').replace("'", '').strip(),
            "severity": "High" if r["prediction_label"].upper() == "DDOS" else "Medium"
        }
        for r in sorted(records, key=lambda x: x["timestamp"], reverse=True)
        if r["prediction_label"].upper() != "BENIGN"
    ][:10]

    # Top malicious source IPs
    from collections import Counter
    malicious_ips = [
        r["flow_key"].split(',')[1].replace("'", '').strip()
        for r in records if r["prediction_label"].upper() != "BENIGN"
    ]
    top_malicious = Counter(malicious_ips).most_common(5)
    top_malicious_ips = [ip for ip, count in top_malicious]
    top_malicious_counts = [count for ip, count in top_malicious]

    return {
        "records": records,
        "donutChart": donut_data,
        "lineChart": line_chart,
        "kpis": {
            "totalRecords": total_records,
            "maliciousCount": malicious_count,
            "safeCount": safe_count,
            "detectionAccuracy": detection_accuracy
        },
        "recentAlerts": recent_alerts,
        "topMaliciousIPs": top_malicious_ips,
        "topMaliciousCounts": top_malicious_counts
    }

# Initialize DB upon import
createDabase()
