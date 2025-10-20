import hashlib
import json
import sqlite3
from datetime import datetime, timezone


def compute_hash(record, prev_hash=""):
    record_str = json.dumps(record, sort_keys=True)
    return hashlib.sha256((prev_hash + record_str).encode()).hexdigest()

def add_entry(db, entry):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ledger (
        ts TEXT,
        method TEXT,
        path TEXT,
        user TEXT,
        status INT,
        body TEXT,
        response TEXT,
        hash TEXT,
        prev_hash TEXT
    )
    """)

    cur.execute("SELECT hash FROM ledger ORDER BY ts DESC LIMIT 1")
    prev_hash = cur.fetchone()
    prev_hash = prev_hash[0] if prev_hash else ""

    entry["ts"] = datetime.now(timezone.utc).isoformat()

    entry["hash"] = compute_hash(entry, prev_hash)
    entry["prev_hash"] = prev_hash

    cur.execute(
    "INSERT INTO ledger VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    (
        entry["ts"],
        entry["method"],
        entry["path"],
        entry["user"],
        entry["status"],
        entry.get("body", ""),
        entry.get("response", ""),
        entry["hash"],
        entry["prev_hash"],
    ),
    )

    conn.commit()
    conn.close()

def verify_ledger(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    rows = cur.execute("SELECT rowid, ts, method, path, user, status, body, response, hash, prev_hash FROM ledger ORDER BY rowid ASC").fetchall()
    conn.close()

    last_hash = ""
    issues = []
    for r in rows:
        rowid, ts, method, path, user, status, body, response, entry_hash, prev_hash = r
        check_str = f"{ts}|{method}|{path}|{user}|{status}|{body}|{response}|{prev_hash}"
        computed_hash = hashlib.sha256(check_str.encode()).hexdigest()

        if prev_hash != last_hash:
            issues.append({"row": rowid, "reason": "Previous hash mismatch", "path": path})
        elif computed_hash != entry_hash:
            issues.append({"row": rowid, "reason": "Hash mismatch", "path": path})
        last_hash = entry_hash

    if issues:
        return {"verified": False, "details": issues}
    return {"verified": True}