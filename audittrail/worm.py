"""
Write-Once-Read-Many (WORM) storage protection for audit trails.
Prevents modification or deletion of audit entries.
"""

import os
import sqlite3
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


# WORM protection database
WORM_DB = os.path.expanduser("~/.audittrail_worm.db")


def init_worm_db():
    """Initialize the WORM protection database."""
    conn = sqlite3.connect(WORM_DB)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS worm_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        db_path TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        row_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        write_token TEXT NOT NULL,
        metadata TEXT,
        UNIQUE(db_path, row_id)
    )
    """)
    
    conn.execute("""
    CREATE TABLE IF NOT EXISTS worm_violations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        db_path TEXT NOT NULL,
        entry_hash TEXT NOT NULL,
        violation_type TEXT NOT NULL,
        detected_at TEXT NOT NULL,
        details TEXT
    )
    """)
    
    conn.commit()
    conn.close()


def generate_write_token(db_path: str, entry_hash: str, row_id: int) -> str:
    """
    Generate a write-once token for an entry.
    
    Args:
        db_path: Path to the audit database
        entry_hash: Hash of the entry
        row_id: Row ID in the database
    
    Returns:
        Write token (hash)
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    token_data = f"{db_path}|{entry_hash}|{row_id}|{timestamp}"
    return hashlib.sha256(token_data.encode()).hexdigest()


def protect_entry(db_path: str, entry_hash: str, row_id: int, metadata: dict = None):
    """
    Mark an entry as write-protected (WORM).
    
    Args:
        db_path: Path to the audit database
        entry_hash: Hash of the entry
        row_id: Row ID in the database
        metadata: Optional metadata
    """
    init_worm_db()
    
    write_token = generate_write_token(db_path, entry_hash, row_id)
    timestamp = datetime.now(timezone.utc).isoformat()
    
    conn = sqlite3.connect(WORM_DB)
    try:
        conn.execute(
            "INSERT INTO worm_entries (db_path, entry_hash, row_id, timestamp, write_token, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (db_path, entry_hash, row_id, timestamp, write_token, json.dumps(metadata) if metadata else None)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # Already protected
        pass
    finally:
        conn.close()


def is_protected(db_path: str, row_id: int) -> bool:
    """
    Check if an entry is WORM-protected.
    
    Args:
        db_path: Path to the audit database
        row_id: Row ID in the database
    
    Returns:
        True if protected, False otherwise
    """
    init_worm_db()
    
    conn = sqlite3.connect(WORM_DB)
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM worm_entries WHERE db_path = ? AND row_id = ?",
        (db_path, row_id)
    )
    count = cur.fetchone()[0]
    conn.close()
    
    return count > 0


def verify_entry_integrity(db_path: str, row_id: int, current_hash: str) -> bool:
    """
    Verify that a protected entry hasn't been modified.
    
    Args:
        db_path: Path to the audit database
        row_id: Row ID in the database
        current_hash: Current hash of the entry
    
    Returns:
        True if integrity verified, False if tampered
    """
    init_worm_db()
    
    conn = sqlite3.connect(WORM_DB)
    cur = conn.cursor()
    cur.execute(
        "SELECT entry_hash FROM worm_entries WHERE db_path = ? AND row_id = ?",
        (db_path, row_id)
    )
    row = cur.fetchone()
    conn.close()
    
    if not row:
        # Not protected
        return True
    
    original_hash = row[0]
    if original_hash != current_hash:
        record_violation(db_path, current_hash, "modification", 
                        {"row_id": row_id, "expected": original_hash, "found": current_hash})
        return False
    
    return True


def record_violation(db_path: str, entry_hash: str, violation_type: str, details: dict = None):
    """
    Record a WORM violation.
    
    Args:
        db_path: Path to the audit database
        entry_hash: Hash of the affected entry
        violation_type: Type of violation (modification, deletion, etc.)
        details: Additional details about the violation
    """
    init_worm_db()
    
    detected_at = datetime.now(timezone.utc).isoformat()
    
    conn = sqlite3.connect(WORM_DB)
    conn.execute(
        "INSERT INTO worm_violations (db_path, entry_hash, violation_type, detected_at, details) "
        "VALUES (?, ?, ?, ?, ?)",
        (db_path, entry_hash, violation_type, detected_at, json.dumps(details) if details else None)
    )
    conn.commit()
    conn.close()


def get_violations(db_path: str = None, limit: int = 100):
    """
    Get WORM violations.
    
    Args:
        db_path: Optional path to filter by database
        limit: Maximum number of violations to return
    
    Returns:
        List of violation records
    """
    init_worm_db()
    
    conn = sqlite3.connect(WORM_DB)
    cur = conn.cursor()
    
    if db_path:
        cur.execute(
            "SELECT id, db_path, entry_hash, violation_type, detected_at, details "
            "FROM worm_violations WHERE db_path = ? ORDER BY id DESC LIMIT ?",
            (db_path, limit)
        )
    else:
        cur.execute(
            "SELECT id, db_path, entry_hash, violation_type, detected_at, details "
            "FROM worm_violations ORDER BY id DESC LIMIT ?",
            (limit,)
        )
    
    rows = cur.fetchall()
    conn.close()
    
    violations = []
    for row in rows:
        violations.append({
            "id": row[0],
            "db_path": row[1],
            "entry_hash": row[2],
            "violation_type": row[3],
            "detected_at": row[4],
            "details": json.loads(row[5]) if row[5] else None
        })
    
    return violations


def get_protection_stats(db_path: str = None):
    """
    Get statistics about WORM protection.
    
    Args:
        db_path: Optional path to filter by database
    
    Returns:
        Dictionary of statistics
    """
    init_worm_db()
    
    conn = sqlite3.connect(WORM_DB)
    cur = conn.cursor()
    
    if db_path:
        protected_count = cur.execute(
            "SELECT COUNT(*) FROM worm_entries WHERE db_path = ?", (db_path,)
        ).fetchone()[0]
        
        violation_count = cur.execute(
            "SELECT COUNT(*) FROM worm_violations WHERE db_path = ?", (db_path,)
        ).fetchone()[0]
    else:
        protected_count = cur.execute(
            "SELECT COUNT(*) FROM worm_entries"
        ).fetchone()[0]
        
        violation_count = cur.execute(
            "SELECT COUNT(*) FROM worm_violations"
        ).fetchone()[0]
    
    conn.close()
    
    return {
        "protected_entries": protected_count,
        "violations_detected": violation_count,
        "integrity_rate": 100.0 if protected_count == 0 else ((protected_count - violation_count) / protected_count * 100)
    }


def enable_worm_for_database(db_path: str):
    """
    Enable WORM protection for all existing entries in a database.
    
    Args:
        db_path: Path to the audit database
    
    Returns:
        Number of entries protected
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    try:
        rows = cur.execute(
            "SELECT rowid, hash FROM ledger ORDER BY rowid ASC"
        ).fetchall()
    except sqlite3.OperationalError:
        # Database doesn't exist or doesn't have ledger table
        conn.close()
        return 0
    
    conn.close()
    
    count = 0
    for row_id, entry_hash in rows:
        if not is_protected(db_path, row_id):
            protect_entry(db_path, entry_hash, row_id)
            count += 1
    
    return count


def verify_worm_integrity(db_path: str):
    """
    Verify WORM integrity for all protected entries.
    
    Args:
        db_path: Path to the audit database
    
    Returns:
        Dictionary with verification results
    """
    # Get all current entries from audit database
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    try:
        current_entries = cur.execute(
            "SELECT rowid, hash FROM ledger ORDER BY rowid ASC"
        ).fetchall()
    except sqlite3.OperationalError:
        conn.close()
        return {"error": "Database not accessible"}
    
    conn.close()
    
    # Check each protected entry
    violations = []
    verified = 0
    
    for row_id, current_hash in current_entries:
        if is_protected(db_path, row_id):
            if verify_entry_integrity(db_path, row_id, current_hash):
                verified += 1
            else:
                violations.append(row_id)
    
    return {
        "total_protected": verified + len(violations),
        "verified": verified,
        "violations": len(violations),
        "violated_rows": violations,
        "integrity_intact": len(violations) == 0
    }

