import hashlib
import json
import sqlite3
import datetime

def compute_hash(record, prev_hash=""):
    record_str = json.dumps(record, sort_keys=True)
    return hashlib.sha256((prev_hash + record_str).encode()).hexdigest()

def add_entry(db, entry):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS ledger (ts TEXT, method TEXT, path TEXT, user TEXT, status INT, hash TEXT, prev_hash TEXT)"
    )

    cur.execute("SELECT hash FROM ledger ORDER BY ts DESC LIMIT 1")
    prev_hash = cur.fetchone()
    prev_hash = prev_hash[0] if prev_hash else ""

    entry["ts"] = datetime.datetime.utcnow().isoformat()
    entry["hash"] = compute_hash(entry, prev_hash)
    entry["prev_hash"] = prev_hash

    cur.execute(
        "INSERT INTO ledger VALUES (?, ?, ?, ?, ?, ?, ?)",
        (entry["ts"], entry["method"], entry["path"], entry["user"], entry["status"], entry["hash"], entry["prev_hash"]),
    )

    conn.commit()
    conn.close()

def verify_ledger(db):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT ts, method, path, user, status, hash, prev_hash FROM ledger ORDER BY ts ASC")
    rows = cur.fetchall()

    prev_hash = ""
    for row in rows:
        record = {
            "ts": row[0],
            "method": row[1],
            "path": row[2],
            "user": row[3],
            "status": row[4],
        }
        calc_hash = compute_hash(record, prev_hash)
        if calc_hash != row[5]:
            conn.close()
            return {"verified": False, "error_at": row[0]}
        prev_hash = row[5]

    conn.close()
    return {"verified": True, "entries": len(rows)}