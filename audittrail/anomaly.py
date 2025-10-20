"""
Anomaly detection and alerting system for audit trails.
Detects suspicious patterns and potential security incidents.
"""

import os
import sqlite3
import json
import smtplib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Anomaly detection database
ANOMALY_DB = os.path.expanduser("~/.audittrail_anomalies.db")
ALERT_CONFIG = os.path.expanduser("~/.audittrail_alerts.json")


def init_anomaly_db():
    """Initialize the anomaly detection database."""
    conn = sqlite3.connect(ANOMALY_DB)
    
    conn.execute("""
    CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detected_at TEXT NOT NULL,
        anomaly_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        db_path TEXT,
        description TEXT NOT NULL,
        details TEXT,
        resolved BOOLEAN DEFAULT 0,
        resolved_at TEXT
    )
    """)
    
    conn.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        anomaly_id INTEGER NOT NULL,
        sent_at TEXT NOT NULL,
        channel TEXT NOT NULL,
        recipient TEXT NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY (anomaly_id) REFERENCES anomalies(id)
    )
    """)
    
    conn.execute("""
    CREATE TABLE IF NOT EXISTS detection_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT NOT NULL UNIQUE,
        rule_type TEXT NOT NULL,
        enabled BOOLEAN DEFAULT 1,
        threshold_value REAL,
        time_window_minutes INTEGER,
        severity TEXT NOT NULL,
        description TEXT
    )
    """)
    
    conn.commit()
    conn.close()


def init_default_rules():
    """Initialize default anomaly detection rules."""
    init_anomaly_db()
    
    default_rules = [
        {
            "rule_name": "rapid_failed_verification",
            "rule_type": "failed_verification",
            "threshold_value": 3,
            "time_window_minutes": 60,
            "severity": "critical",
            "description": "Multiple failed ledger verifications in short time"
        },
        {
            "rule_name": "suspicious_access_pattern",
            "rule_type": "access_pattern",
            "threshold_value": 100,
            "time_window_minutes": 5,
            "severity": "high",
            "description": "Unusually high number of log accesses"
        },
        {
            "rule_name": "worm_violation",
            "rule_type": "integrity_violation",
            "threshold_value": 1,
            "time_window_minutes": 1,
            "severity": "critical",
            "description": "WORM integrity violation detected"
        },
        {
            "rule_name": "signature_mismatch",
            "rule_type": "signature_error",
            "threshold_value": 1,
            "time_window_minutes": 1,
            "severity": "critical",
            "description": "Digital signature verification failed"
        },
        {
            "rule_name": "unusual_delete_attempt",
            "rule_type": "deletion_attempt",
            "threshold_value": 1,
            "time_window_minutes": 1,
            "severity": "high",
            "description": "Attempt to delete audit entries"
        },
        {
            "rule_name": "timestamp_anomaly",
            "rule_type": "timestamp_error",
            "threshold_value": 5,
            "time_window_minutes": 60,
            "severity": "medium",
            "description": "Timestamp inconsistencies detected"
        },
        {
            "rule_name": "unauthorized_access_spike",
            "rule_type": "unauthorized_access",
            "threshold_value": 10,
            "time_window_minutes": 10,
            "severity": "high",
            "description": "High rate of unauthorized access attempts"
        }
    ]
    
    conn = sqlite3.connect(ANOMALY_DB)
    cur = conn.cursor()
    
    for rule in default_rules:
        try:
            cur.execute(
                "INSERT INTO detection_rules (rule_name, rule_type, threshold_value, time_window_minutes, severity, description) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (rule["rule_name"], rule["rule_type"], rule["threshold_value"], 
                 rule["time_window_minutes"], rule["severity"], rule["description"])
            )
        except sqlite3.IntegrityError:
            # Rule already exists
            pass
    
    conn.commit()
    conn.close()


def record_anomaly(anomaly_type: str, severity: str, description: str, 
                   db_path: str = None, details: Dict = None) -> int:
    """
    Record a detected anomaly.
    
    Args:
        anomaly_type: Type of anomaly
        severity: Severity level (low, medium, high, critical)
        description: Human-readable description
        db_path: Optional path to affected database
        details: Additional details
    
    Returns:
        Anomaly ID
    """
    init_anomaly_db()
    
    detected_at = datetime.now(timezone.utc).isoformat()
    
    conn = sqlite3.connect(ANOMALY_DB)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO anomalies (detected_at, anomaly_type, severity, db_path, description, details) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (detected_at, anomaly_type, severity, db_path, description, 
         json.dumps(details) if details else None)
    )
    anomaly_id = cur.lastrowid
    conn.commit()
    conn.close()
    
    # Trigger alerts
    send_alerts_for_anomaly(anomaly_id, anomaly_type, severity, description)
    
    return anomaly_id


def send_alerts_for_anomaly(anomaly_id: int, anomaly_type: str, severity: str, description: str):
    """
    Send alerts for a detected anomaly based on configured channels.
    
    Args:
        anomaly_id: ID of the anomaly
        anomaly_type: Type of anomaly
        severity: Severity level
        description: Description of the anomaly
    """
    config = load_alert_config()
    
    if not config.get("enabled", False):
        return
    
    # Severity threshold check
    severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    min_severity = severity_levels.get(config.get("min_severity", "medium"), 2)
    current_severity = severity_levels.get(severity, 1)
    
    if current_severity < min_severity:
        return
    
    sent_at = datetime.now(timezone.utc).isoformat()
    
    init_anomaly_db()
    conn = sqlite3.connect(ANOMALY_DB)
    
    # Log alerts (actual sending would happen here)
    for channel in config.get("channels", []):
        if channel.get("enabled", False):
            channel_type = channel.get("type")
            
            if channel_type == "log":
                # Already logged in anomalies table
                status = "logged"
            elif channel_type == "email":
                status = "configured"  # Would actually send email
            elif channel_type == "webhook":
                status = "configured"  # Would actually call webhook
            else:
                status = "unknown"
            
            conn.execute(
                "INSERT INTO alerts (anomaly_id, sent_at, channel, recipient, status) "
                "VALUES (?, ?, ?, ?, ?)",
                (anomaly_id, sent_at, channel_type, 
                 channel.get("recipient", ""), status)
            )
    
    conn.commit()
    conn.close()


def load_alert_config() -> Dict:
    """Load alert configuration."""
    if not os.path.exists(ALERT_CONFIG):
        # Create default config
        default_config = {
            "enabled": True,
            "min_severity": "high",
            "channels": [
                {
                    "type": "log",
                    "enabled": True
                }
            ]
        }
        save_alert_config(default_config)
        return default_config
    
    with open(ALERT_CONFIG, 'r') as f:
        return json.load(f)


def save_alert_config(config: Dict):
    """Save alert configuration."""
    with open(ALERT_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)
    os.chmod(ALERT_CONFIG, 0o600)


def detect_failed_verification_spike(db_path: str, time_window_minutes: int = 60) -> Optional[int]:
    """
    Detect if there are multiple failed verifications in a time window.
    
    Args:
        db_path: Database path
        time_window_minutes: Time window to check
    
    Returns:
        Anomaly ID if detected, None otherwise
    """
    # This would check CLI audit logs for failed verification attempts
    from .auth import CLI_AUDIT_PATH
    
    if not os.path.exists(CLI_AUDIT_PATH):
        return None
    
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    
    conn = sqlite3.connect(CLI_AUDIT_PATH)
    cur = conn.cursor()
    
    try:
        count = cur.execute(
            "SELECT COUNT(*) FROM cli_audit WHERE command = 'verify' AND success = 0 AND timestamp > ?",
            (cutoff_time.isoformat(),)
        ).fetchone()[0]
    except sqlite3.OperationalError:
        conn.close()
        return None
    
    conn.close()
    
    # Check against rule threshold
    rule = get_rule("rapid_failed_verification")
    if rule and count >= rule["threshold_value"]:
        return record_anomaly(
            "failed_verification",
            "critical",
            f"Detected {count} failed verification attempts in {time_window_minutes} minutes",
            db_path,
            {"count": count, "time_window": time_window_minutes}
        )
    
    return None


def detect_access_pattern_anomaly(db_path: str, time_window_minutes: int = 5) -> Optional[int]:
    """
    Detect unusual access patterns.
    
    Args:
        db_path: Database path
        time_window_minutes: Time window to check
    
    Returns:
        Anomaly ID if detected, None otherwise
    """
    from .auth import CLI_AUDIT_PATH
    
    if not os.path.exists(CLI_AUDIT_PATH):
        return None
    
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    
    conn = sqlite3.connect(CLI_AUDIT_PATH)
    cur = conn.cursor()
    
    try:
        count = cur.execute(
            "SELECT COUNT(*) FROM cli_audit WHERE timestamp > ?",
            (cutoff_time.isoformat(),)
        ).fetchone()[0]
    except sqlite3.OperationalError:
        conn.close()
        return None
    
    conn.close()
    
    rule = get_rule("suspicious_access_pattern")
    if rule and count >= rule["threshold_value"]:
        return record_anomaly(
            "access_pattern",
            "high",
            f"Detected {count} access operations in {time_window_minutes} minutes",
            db_path,
            {"count": count, "time_window": time_window_minutes}
        )
    
    return None


def get_rule(rule_name: str) -> Optional[Dict]:
    """Get a detection rule by name."""
    init_anomaly_db()
    
    conn = sqlite3.connect(ANOMALY_DB)
    cur = conn.cursor()
    cur.execute(
        "SELECT rule_type, enabled, threshold_value, time_window_minutes, severity, description "
        "FROM detection_rules WHERE rule_name = ?",
        (rule_name,)
    )
    row = cur.fetchone()
    conn.close()
    
    if not row:
        return None
    
    return {
        "rule_name": rule_name,
        "rule_type": row[0],
        "enabled": bool(row[1]),
        "threshold_value": row[2],
        "time_window_minutes": row[3],
        "severity": row[4],
        "description": row[5]
    }


def get_recent_anomalies(limit: int = 50, unresolved_only: bool = False) -> List[Dict]:
    """
    Get recent anomalies.
    
    Args:
        limit: Maximum number to return
        unresolved_only: Only return unresolved anomalies
    
    Returns:
        List of anomaly records
    """
    init_anomaly_db()
    
    conn = sqlite3.connect(ANOMALY_DB)
    cur = conn.cursor()
    
    if unresolved_only:
        cur.execute(
            "SELECT id, detected_at, anomaly_type, severity, db_path, description, details "
            "FROM anomalies WHERE resolved = 0 ORDER BY id DESC LIMIT ?",
            (limit,)
        )
    else:
        cur.execute(
            "SELECT id, detected_at, anomaly_type, severity, db_path, description, details, resolved "
            "FROM anomalies ORDER BY id DESC LIMIT ?",
            (limit,)
        )
    
    rows = cur.fetchall()
    conn.close()
    
    anomalies = []
    for row in rows:
        anomalies.append({
            "id": row[0],
            "detected_at": row[1],
            "anomaly_type": row[2],
            "severity": row[3],
            "db_path": row[4],
            "description": row[5],
            "details": json.loads(row[6]) if row[6] else None,
            "resolved": bool(row[7]) if len(row) > 7 else None
        })
    
    return anomalies


def resolve_anomaly(anomaly_id: int):
    """Mark an anomaly as resolved."""
    init_anomaly_db()
    
    resolved_at = datetime.now(timezone.utc).isoformat()
    
    conn = sqlite3.connect(ANOMALY_DB)
    conn.execute(
        "UPDATE anomalies SET resolved = 1, resolved_at = ? WHERE id = ?",
        (resolved_at, anomaly_id)
    )
    conn.commit()
    conn.close()


def get_anomaly_statistics() -> Dict:
    """Get statistics about detected anomalies."""
    init_anomaly_db()
    
    conn = sqlite3.connect(ANOMALY_DB)
    cur = conn.cursor()
    
    total = cur.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    unresolved = cur.execute("SELECT COUNT(*) FROM anomalies WHERE resolved = 0").fetchone()[0]
    
    by_severity = cur.execute(
        "SELECT severity, COUNT(*) FROM anomalies GROUP BY severity"
    ).fetchall()
    
    by_type = cur.execute(
        "SELECT anomaly_type, COUNT(*) FROM anomalies GROUP BY anomaly_type"
    ).fetchall()
    
    recent_24h = cur.execute(
        "SELECT COUNT(*) FROM anomalies WHERE detected_at > ?",
        ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),)
    ).fetchone()[0]
    
    conn.close()
    
    return {
        "total_anomalies": total,
        "unresolved": unresolved,
        "by_severity": dict(by_severity),
        "by_type": dict(by_type),
        "last_24_hours": recent_24h
    }


def run_all_detections(db_path: str) -> List[int]:
    """
    Run all enabled detection rules.
    
    Args:
        db_path: Database path to check
    
    Returns:
        List of anomaly IDs that were detected
    """
    anomaly_ids = []
    
    # Run each detection
    result = detect_failed_verification_spike(db_path)
    if result:
        anomaly_ids.append(result)
    
    result = detect_access_pattern_anomaly(db_path)
    if result:
        anomaly_ids.append(result)
    
    return anomaly_ids

