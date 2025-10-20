"""
Authentication and authorization module for AuditTrail CLI.
Implements role-based access control (RBAC) with three roles:
- viewer: can view encrypted logs
- verifier: can verify logs and view encrypted logs
- admin: full access including decryption
"""

import json
import os
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone
import sqlite3

# User roles configuration
ROLES_PATH = os.path.expanduser("~/.audittrail_users.json")
CLI_AUDIT_PATH = os.path.expanduser("~/.audittrail_cli_audit.db")

# Role definitions
ROLES = {
    "viewer": {
        "description": "Can view encrypted logs",
        "permissions": ["logs", "search", "stats", "watch"]
    },
    "verifier": {
        "description": "Can verify logs and view encrypted logs",
        "permissions": ["logs", "search", "stats", "watch", "verify", "export", "verify_enhanced"]
    },
    "admin": {
        "description": "Full access including decryption and user management",
        "permissions": ["logs", "search", "stats", "watch", "verify", "export", "decrypt", "clear", "init", 
                       "add-user", "list-users", "remove-user", "audit-logs", "verify_enhanced", "worm_status", 
                       "enable_worm", "init_signing", "anomalies", "resolve_anomaly", "compliance_report", 
                       "compliance_status", "admin"]
    }
}


def init_cli_audit_db():
    """Initialize the CLI audit log database."""
    conn = sqlite3.connect(CLI_AUDIT_PATH)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS cli_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        role TEXT NOT NULL,
        command TEXT NOT NULL,
        args TEXT,
        success BOOLEAN NOT NULL,
        error TEXT
    )
    """)
    conn.commit()
    conn.close()


def log_cli_operation(username, role, command, args="", success=True, error=None):
    """Log a CLI operation to the audit trail."""
    init_cli_audit_db()
    conn = sqlite3.connect(CLI_AUDIT_PATH)
    conn.execute(
        "INSERT INTO cli_audit (timestamp, username, role, command, args, success, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), username, role, command, args, success, error)
    )
    conn.commit()
    conn.close()


def hash_password(password):
    """Hash a password with a random salt."""
    salt = secrets.token_hex(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${pwdhash.hex()}"


def verify_password(stored_password, provided_password):
    """Verify a password against the stored hash."""
    salt, pwdhash = stored_password.split('$')
    computed_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt.encode(), 100000)
    return computed_hash.hex() == pwdhash


def init_users_file():
    """Initialize the users file if it doesn't exist."""
    if not os.path.exists(ROLES_PATH):
        # Create with a default admin user (password: admin)
        default_users = {
            "admin": {
                "password": hash_password("admin"),
                "role": "admin",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
        }
        with open(ROLES_PATH, 'w') as f:
            json.dump(default_users, f, indent=2)
        os.chmod(ROLES_PATH, 0o600)  # Restrict permissions
        return True
    return False


def add_user(username, password, role):
    """Add a new user with specified role."""
    if role not in ROLES:
        raise ValueError(f"Invalid role. Must be one of: {', '.join(ROLES.keys())}")
    
    init_users_file()
    
    with open(ROLES_PATH, 'r') as f:
        users = json.load(f)
    
    if username in users:
        raise ValueError(f"User '{username}' already exists")
    
    users[username] = {
        "password": hash_password(password),
        "role": role,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    with open(ROLES_PATH, 'w') as f:
        json.dump(users, f, indent=2)
    
    return True


def remove_user(username):
    """Remove a user."""
    if not os.path.exists(ROLES_PATH):
        raise ValueError("No users configured")
    
    with open(ROLES_PATH, 'r') as f:
        users = json.load(f)
    
    if username not in users:
        raise ValueError(f"User '{username}' does not exist")
    
    if username == "admin" and len([u for u in users if users[u]["role"] == "admin"]) == 1:
        raise ValueError("Cannot remove the last admin user")
    
    del users[username]
    
    with open(ROLES_PATH, 'w') as f:
        json.dump(users, f, indent=2)
    
    return True


def list_users():
    """List all users and their roles."""
    if not os.path.exists(ROLES_PATH):
        return {}
    
    with open(ROLES_PATH, 'r') as f:
        users = json.load(f)
    
    # Return without passwords
    return {
        username: {
            "role": user["role"],
            "created_at": user["created_at"]
        }
        for username, user in users.items()
    }


def authenticate(username, password):
    """Authenticate a user and return their role."""
    init_users_file()
    
    with open(ROLES_PATH, 'r') as f:
        users = json.load(f)
    
    if username not in users:
        return None
    
    if verify_password(users[username]["password"], password):
        return users[username]["role"]
    
    return None


def check_permission(role, command):
    """Check if a role has permission to execute a command."""
    if role not in ROLES:
        return False
    return command in ROLES[role]["permissions"]


def get_current_session():
    """Get the current authenticated session."""
    session_file = os.path.expanduser("~/.audittrail_session.json")
    if os.path.exists(session_file):
        with open(session_file, 'r') as f:
            session = json.load(f)
            # Check if session is still valid (24 hours)
            from datetime import datetime, timedelta
            created = datetime.fromisoformat(session["created_at"])
            if datetime.now() - created < timedelta(hours=24):
                return session
    return None


def create_session(username, role):
    """Create a new authenticated session."""
    session_file = os.path.expanduser("~/.audittrail_session.json")
    session = {
        "username": username,
        "role": role,
        "created_at": datetime.now().isoformat()
    }
    with open(session_file, 'w') as f:
        json.dump(session, f, indent=2)
    os.chmod(session_file, 0o600)
    return session


def clear_session():
    """Clear the current session."""
    session_file = os.path.expanduser("~/.audittrail_session.json")
    if os.path.exists(session_file):
        os.remove(session_file)

