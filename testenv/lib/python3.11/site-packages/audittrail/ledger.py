"""
Ledger module with optional compliance features:
- Digital signatures
- Timestamp authorities
- WORM protection
- Anomaly detection
"""

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from cryptography.fernet import Fernet
from typing import Optional, Dict, Any

# Import compliance modules (optional)
try:
    from .signatures import sign_entry, verify_entry_signature, initialize_signing_keys
    from .timestamp import create_local_timestamp, get_timestamp
    from .worm import protect_entry, verify_entry_integrity
    from .anomaly import record_anomaly
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False

# --- must match middleware ---
KEY_PATH = os.path.expanduser("~/.audittrail.key")
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, "wb") as f:
        f.write(Fernet.generate_key())
with open(KEY_PATH, "rb") as f:
    CIPHER = Fernet(f.read())
key_id = os.getenv("AUDITTRAIL_KEY_ID", "local")


def _ensure_db(db):
    """Ensure database exists with schema supporting compliance features."""
    conn = sqlite3.connect(db)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS ledger (
        ts TEXT,
        method TEXT,
        path TEXT,
        user TEXT,
        status INT,
        body TEXT,
        response TEXT,
        hash TEXT,
        prev_hash TEXT,
        key_id TEXT DEFAULT 'local',
        signature TEXT,
        timestamp_token TEXT,
        worm_protected INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()


def _encrypt_body(value) -> str:
    """
    Accepts dict/str/bytes/None and returns base64-url string (Fernet token, decoded).
    Matches middleware behavior:
      - request body is JSON-dumped with sort_keys=True (when parseable) before encrypt
      - response is raw bytes encrypted
    """
    if value is None:
        s = ""
        return CIPHER.encrypt(s.encode()).decode()

    # If already bytes, encrypt directly (like response in middleware)
    if isinstance(value, (bytes, bytearray)):
        return CIPHER.encrypt(bytes(value)).decode()

    # If it's JSON-like, normalize deterministically
    if isinstance(value, (dict, list)):
        s = json.dumps(value, sort_keys=True)
        return CIPHER.encrypt(s.encode()).decode()

    # Try to interpret string as JSON; if that fails, encrypt the raw string
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            s = json.dumps(parsed, sort_keys=True)
        except Exception:
            s = value
        return CIPHER.encrypt(s.encode()).decode()

    # Fallback: stringify then encrypt
    s = str(value)
    return CIPHER.encrypt(s.encode()).decode()


def _compute_hash_string(ts, method, path, user, status, enc_body, enc_resp, prev_hash, key_id) -> str:
    entry_str = f"{ts}|{method}|{path}|{user}|{status}|{enc_body}|{enc_resp}|{prev_hash}|{key_id}"
    return hashlib.sha256(entry_str.encode()).hexdigest()


def add_entry(db, entry, enable_compliance=True):
    """
    Add entry with optional compliance features.
    
    Args:
        db: Database path
        entry: Entry data (method, path, user, status, body, response)
        enable_compliance: Enable signatures, timestamps, and WORM (default: True)
    
    Returns:
        Entry hash
    
    Example:
        add_entry("audit_log.db", {
            "method": "POST",
            "path": "/transfer",
            "user": "user@example.com",
            "status": 200,
            "body": {"amount": 1000},
            "response": {"success": True}
        })
    """
    _ensure_db(db)

    conn = sqlite3.connect(db)
    cur = conn.cursor()

    # Get previous hash (latest by timestamp, same as middleware)
    cur.execute("SELECT hash FROM ledger ORDER BY ts DESC LIMIT 1")
    prev = cur.fetchone()
    prev_hash = prev[0] if prev else ""

    ts = datetime.now(timezone.utc).isoformat()

    # Encrypt body/response BEFORE hashing, mirroring middleware
    enc_body = _encrypt_body(entry.get("body", ""))
    # Response might be bytes in your app; we accept either
    enc_resp = _encrypt_body(entry.get("response", ""))

    # Compute hash on the exact same string the middleware uses
    entry_hash = _compute_hash_string(
        ts,
        entry["method"],
        entry["path"],
        entry["user"],
        int(entry["status"]),
        enc_body,
        enc_resp,
        prev_hash,
        key_id
    )

    # Initialize compliance features if needed
    signature = None
    timestamp_token = None
    worm_protected = 0

    if enable_compliance and COMPLIANCE_AVAILABLE:
        # Initialize signing keys if they don't exist
        try:
            initialize_signing_keys()
        except Exception:
            pass

        # Create digital signature
        try:
            signature_data = {
                "ts": ts,
                "method": entry["method"],
                "path": entry["path"],
                "user": entry["user"],
                "status": int(entry["status"]),
                "hash": entry_hash,
                "prev_hash": prev_hash
            }
            signature = sign_entry(signature_data)
        except Exception as e:
            # Log signature failure
            if COMPLIANCE_AVAILABLE:
                record_anomaly("signature_error", "high", 
                             f"Failed to sign entry: {str(e)}", db)

        # Create timestamp
        try:
            ts_info = create_local_timestamp(entry_hash, {"db": db, "ts": ts})
            timestamp_token = ts_info["token"]
        except Exception:
            pass

        # Mark for WORM protection
        worm_protected = 1

    # Store encrypted body/response and the chain
    cur.execute(
        "INSERT INTO ledger (ts, method, path, user, status, body, response, hash, prev_hash, key_id, signature, timestamp_token, worm_protected) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ts,
            entry["method"],
            entry["path"],
            entry["user"],
            int(entry["status"]),
            enc_body,
            enc_resp,
            entry_hash,
            prev_hash,
            key_id,
            signature,
            timestamp_token,
            worm_protected
        ),
    )

    row_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Apply WORM protection after insertion
    if worm_protected and COMPLIANCE_AVAILABLE:
        try:
            protect_entry(db, entry_hash, row_id, {"ts": ts})
        except Exception:
            pass

    return entry_hash


def verify_ledger(db_path, check_signatures=True, check_worm=True):
    """
    Verify ledger with optional compliance checks.
    
    Recomputes the hash using the stored (already encrypted) body/response strings,
    matching the middleware's entry_str computation. No decryption required.
    
    Args:
        db_path: Database path
        check_signatures: Verify digital signatures (default: True)
        check_worm: Check WORM integrity (default: True)
    
    Returns:
        Verification results dictionary with:
        - verified: bool
        - total_entries: int
        - issues: int
        - details: list (if issues found)
        - signature_failures: int (if signatures checked)
        - worm_violations: int (if WORM checked)
    
    Example:
        result = verify_ledger("audit_log.db")
        if result["verified"]:
            print("Ledger is valid!")
        else:
            print(f"Issues found: {result['details']}")
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Check if compliance columns exist
    columns = [col[1] for col in cur.execute("PRAGMA table_info(ledger)").fetchall()]
    has_signatures = "signature" in columns
    has_worm = "worm_protected" in columns
    
    if has_signatures and has_worm:
        rows = cur.execute(
            "SELECT rowid, ts, method, path, user, status, body, response, hash, prev_hash, key_id, signature, worm_protected "
            "FROM ledger ORDER BY rowid ASC"
        ).fetchall()
    else:
        rows = cur.execute(
            "SELECT rowid, ts, method, path, user, status, body, response, hash, prev_hash, key_id "
            "FROM ledger ORDER BY rowid ASC"
        ).fetchall()
    
    conn.close()

    last_hash = ""
    issues = []
    signature_failures = 0
    worm_violations = 0
    
    for r in rows:
        if has_signatures and has_worm:
            rowid, ts, method, path, user, status, body, response, entry_hash, prev_hash, kid, signature, worm_protected = r
        else:
            rowid, ts, method, path, user, status, body, response, entry_hash, prev_hash, kid = r
            signature = None
            worm_protected = 0

        # 1) Chain check
        if prev_hash != last_hash:
            issues.append({"row": rowid, "reason": "Previous hash mismatch", "path": path})

        # 2) Integrity check (use stored encrypted values exactly as middleware hashed)
        computed_hash = _compute_hash_string(
            ts, method, path, user, int(status), body, response, prev_hash, kid
        )
        if computed_hash != entry_hash:
            issues.append({"row": rowid, "reason": "Hash mismatch", "path": path})

        # 3) Signature verification
        if check_signatures and signature and COMPLIANCE_AVAILABLE:
            try:
                signature_data = {
                    "ts": ts,
                    "method": method,
                    "path": path,
                    "user": user,
                    "status": int(status),
                    "hash": entry_hash,
                    "prev_hash": prev_hash
                }
                if not verify_entry_signature(signature_data, signature):
                    issues.append({"row": rowid, "reason": "Signature verification failed", "path": path})
                    signature_failures += 1
            except Exception as e:
                issues.append({"row": rowid, "reason": f"Signature check error: {str(e)}", "path": path})

        # 4) WORM integrity check
        if check_worm and worm_protected and COMPLIANCE_AVAILABLE:
            try:
                if not verify_entry_integrity(db_path, rowid, entry_hash):
                    issues.append({"row": rowid, "reason": "WORM integrity violation", "path": path})
                    worm_violations += 1
            except Exception:
                pass

        last_hash = entry_hash

    # Record anomalies if issues found
    if issues and COMPLIANCE_AVAILABLE:
        if signature_failures > 0:
            record_anomaly("signature_error", "critical",
                         f"Found {signature_failures} signature verification failures", db_path)
        if worm_violations > 0:
            record_anomaly("integrity_violation", "critical",
                         f"Found {worm_violations} WORM violations", db_path)

    result = {
        "verified": len(issues) == 0,
        "total_entries": len(rows),
        "issues": len(issues)
    }
    
    if issues:
        result["details"] = issues
    
    if has_signatures:
        result["signature_failures"] = signature_failures
    
    if has_worm:
        result["worm_violations"] = worm_violations
    
    return result
