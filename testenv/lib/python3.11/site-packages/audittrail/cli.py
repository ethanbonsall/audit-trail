import click
import sqlite3
import json
import csv
import time
import os
from functools import wraps
from .ledger import verify_ledger
from .auth import (
    authenticate, check_permission, get_current_session, create_session, clear_session,
    add_user as auth_add_user, remove_user as auth_remove_user, list_users as auth_list_users,
    log_cli_operation, ROLES, init_users_file, CLI_AUDIT_PATH
)
from cryptography.fernet import Fernet
from tabulate import tabulate


KEY_PATH = os.path.expanduser("~/.audittrail.key")

def load_cipher():
    if not os.path.exists(KEY_PATH):
        raise click.ClickException("Encryption key not found. Run your API once to generate ~/.audittrail.key.")
    with open(KEY_PATH, "rb") as f:
        return Fernet(f.read())


def print_table(rows, headers):
    """Pretty print rows using tabulate."""
    if not rows:
        click.echo(click.style("No log entries found.", fg="yellow"))
        return

    table = tabulate(rows, headers=headers, tablefmt="fancy_grid", stralign="left", maxcolwidths=[30]*len(headers))
    click.echo(table)


def color_status(status):
    """Color HTTP status codes for clarity."""
    if status < 300:
        return click.style(str(status), fg="green")
    elif status < 400:
        return click.style(str(status), fg="yellow")
    else:
        return click.style(str(status), fg="red")


def require_auth(command_name):
    """Decorator to require authentication and check permissions."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            session = get_current_session()
            
            if not session:
                click.echo(click.style("Authentication required. Please login first.", fg="red"))
                click.echo(click.style("Run: audittrail login", fg="yellow"))
                return
            
            username = session["username"]
            role = session["role"]
            
            # Check if user has permission for this command
            if not check_permission(role, command_name):
                log_cli_operation(username, role, command_name, success=False, error="Permission denied")
                click.echo(click.style(f"Permission denied. Your role '{role}' cannot execute '{command_name}'.", fg="red"))
                click.echo(click.style(f"Required permissions: {', '.join([r for r, perms in ROLES.items() if command_name in perms['permissions']])}", fg="yellow"))
                return
            
            # Log the operation
            try:
                result = f(*args, **kwargs)
                log_cli_operation(username, role, command_name, args=str(kwargs), success=True)
                return result
            except Exception as e:
                log_cli_operation(username, role, command_name, args=str(kwargs), success=False, error=str(e))
                raise
        
        return wrapper
    return decorator


@click.group()
def cli():
    """AuditTrail CLI — Verify, inspect, and manage audit logs with role-based access control."""
    # Initialize users file on first run
    if init_users_file():
        click.echo(click.style("⚠️  First run detected. Created default admin user.", fg="yellow"))
        click.echo(click.style("Username: admin | Password: admin", fg="yellow"))
        click.echo(click.style("Please change the password immediately using 'audittrail change-password'", fg="red", bold=True))


# ==================== Authentication Commands ====================

@cli.command()
@click.option("--username", prompt=True, help="Username")
@click.option("--password", prompt=True, hide_input=True, help="Password")
def login(username, password):
    """Login to the AuditTrail CLI."""
    role = authenticate(username, password)
    
    if role:
        create_session(username, role)
        click.echo(click.style(f"✓ Login successful. Welcome, {username}!", fg="green"))
        click.echo(click.style(f"Role: {role} ({ROLES[role]['description']})", fg="cyan"))
        log_cli_operation(username, role, "login", success=True)
    else:
        click.echo(click.style("✗ Authentication failed. Invalid username or password.", fg="red"))


@cli.command()
def logout():
    """Logout from the current session."""
    session = get_current_session()
    if session:
        log_cli_operation(session["username"], session["role"], "logout", success=True)
        clear_session()
        click.echo(click.style("✓ Logged out successfully.", fg="green"))
    else:
        click.echo(click.style("No active session found.", fg="yellow"))


@cli.command()
def whoami():
    """Show current user session information."""
    session = get_current_session()
    if session:
        click.echo(click.style(f"Username: {session['username']}", fg="cyan"))
        click.echo(click.style(f"Role: {session['role']}", fg="cyan"))
        click.echo(click.style(f"Permissions: {', '.join(ROLES[session['role']]['permissions'])}", fg="cyan"))
        click.echo(click.style(f"Session created: {session['created_at']}", fg="cyan"))
    else:
        click.echo(click.style("Not logged in.", fg="yellow"))


@cli.command()
@click.option("--old-password", prompt=True, hide_input=True, help="Current password")
@click.option("--new-password", prompt=True, hide_input=True, confirmation_prompt=True, help="New password")
def change_password(old_password, new_password):
    """Change your password."""
    session = get_current_session()
    if not session:
        click.echo(click.style("Please login first.", fg="red"))
        return
    
    username = session["username"]
    
    # Verify old password
    if not authenticate(username, old_password):
        click.echo(click.style("✗ Current password is incorrect.", fg="red"))
        return
    
    # Change password by removing and re-adding user
    try:
        role = session["role"]
        auth_remove_user(username)
        auth_add_user(username, new_password, role)
        click.echo(click.style("✓ Password changed successfully.", fg="green"))
        log_cli_operation(username, role, "change_password", success=True)
    except Exception as e:
        click.echo(click.style(f"✗ Error changing password: {e}", fg="red"))


# ==================== User Management Commands (Admin Only) ====================

@cli.command()
@click.option("--username", prompt=True, help="New username")
@click.option("--password", prompt=True, hide_input=True, confirmation_prompt=True, help="Password")
@click.option("--role", type=click.Choice(["viewer", "verifier", "admin"]), prompt=True, help="User role")
@require_auth("add-user")
def add_user(username, password, role):
    """Add a new user (admin only)."""
    try:
        auth_add_user(username, password, role)
        click.echo(click.style(f"✓ User '{username}' created with role '{role}'.", fg="green"))
    except ValueError as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red"))


@cli.command()
@click.argument("username")
@click.confirmation_option(prompt="Are you sure you want to remove this user?")
@require_auth("remove-user")
def remove_user(username):
    """Remove a user (admin only)."""
    try:
        auth_remove_user(username)
        click.echo(click.style(f"✓ User '{username}' removed.", fg="green"))
    except ValueError as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red"))


@cli.command()
@require_auth("list-users")
def list_users():
    """List all users (admin only)."""
    users = auth_list_users()
    
    if not users:
        click.echo(click.style("No users found.", fg="yellow"))
        return
    
    headers = ["Username", "Role", "Created At"]
    rows = [[username, info["role"], info["created_at"]] for username, info in users.items()]
    print_table(rows, headers)


# ==================== Audit Log Commands ====================

@cli.command()
@click.argument("db_path")
@require_auth("verify")
def verify(db_path):
    """Verify the integrity of the ledger (verifier, admin)."""
    result = verify_ledger(db_path)
    if result.get("verified"):
        click.echo(click.style("✓ Ledger verified successfully — no tampering detected.", fg="green"))
    else:
        click.echo(click.style("✗ Ledger verification FAILED", fg="red", bold=True))
        if "details" in result:
            for issue in result["details"]:
                click.echo(click.style(f"  - Row {issue['row']}: {issue['reason']}", fg="yellow"))
        else:
            click.echo(click.style(f"  Reason: {result.get('error', 'Unknown error')}", fg="yellow"))


@cli.command()
@click.argument("db_path")
@click.option("--limit", default=10, help="Number of recent entries to show")
@click.option("--decrypt", is_flag=True, help="Decrypt and show request/response bodies (admin only)")
@require_auth("logs")
def logs(db_path, limit, decrypt):
    """Show recent log entries (all roles, decrypt requires admin)."""
    session = get_current_session()
    
    # Check decrypt permission
    if decrypt and not check_permission(session["role"], "decrypt"):
        click.echo(click.style("✗ Decryption requires admin role.", fg="red"))
        return
    
    conn = sqlite3.connect(db_path)
    
    if decrypt:
        rows = conn.execute(
            "SELECT ts, method, path, user, status, body, response FROM ledger ORDER BY ts DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        
        cipher = load_cipher()
        headers = ["Timestamp", "Method", "Path", "User", "Status", "Request Body", "Response"]
        rows_for_table = []
        for r in rows:
            dec_body = cipher.decrypt(r[5].encode()).decode(errors="ignore") if r[5] else ""
            dec_resp = cipher.decrypt(r[6].encode()).decode(errors="ignore") if r[6] else ""
            rows_for_table.append([r[0], r[1], r[2], r[3], r[4], dec_body[:50], dec_resp[:50]])
    else:
        rows = conn.execute(
            "SELECT ts, method, path, user, status FROM ledger ORDER BY ts DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        
        headers = ["Timestamp", "Method", "Path", "User", "Status"]
        rows_for_table = [[r[0], r[1], r[2], r[3], r[4]] for r in rows]
    
    click.echo(click.style(f"Last {len(rows)} log entries:\n", bold=True))
    print_table(rows_for_table, headers)


@cli.command()
@click.argument("db_path")
@click.option("--user", help="Filter by user")
@click.option("--path", help="Filter by endpoint path")
@require_auth("search")
def search(db_path, user, path):
    """Search entries by user or endpoint (all roles)."""
    conn = sqlite3.connect(db_path)
    q = "SELECT ts, method, path, user, status FROM ledger WHERE 1=1"
    p = []
    if user:
        q += " AND user LIKE ?"
        p.append(f"%{user}%")
    if path:
        q += " AND path LIKE ?"
        p.append(f"%{path}%")
    rows = conn.execute(q + " ORDER BY ts DESC LIMIT 50", p).fetchall()
    conn.close()

    if not rows:
        click.echo(click.style("No matching entries found.", fg="yellow"))
        return

    click.echo(click.style(f"Found {len(rows)} entries:\n", bold=True))
    headers = ["Timestamp", "Method", "Path", "User", "Status"]
    rows_for_table = [[r[0], r[1], r[2], r[3], r[4]] for r in rows]
    print_table(rows_for_table, headers)


@cli.command()
@click.argument("db_path")
@click.option("--format", type=click.Choice(["json", "csv"]), default="json")
@click.option("--out", default="audit_export.json")
@require_auth("export")
def export(db_path, format, out):
    """Export all logs to JSON or CSV (verifier, admin)."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("SELECT * FROM ledger").fetchall()
    cols = [d[1] for d in conn.execute("PRAGMA table_info(ledger)").fetchall()]

    if format == "json":
        data = [dict(zip(cols, r)) for r in rows]
        with open(out, "w") as f:
            json.dump(data, f, indent=2)
    else:
        with open(out, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(cols)
            writer.writerows(rows)
    conn.close()
    click.echo(click.style(f"✓ Exported {len(rows)} entries to {out}", fg="green"))


@cli.command()
@click.argument("db_path")
@require_auth("stats")
def stats(db_path):
    """Show ledger statistics (all roles)."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
    users = cur.execute("SELECT COUNT(DISTINCT user) FROM ledger").fetchone()[0]
    methods = cur.execute("SELECT method, COUNT(*) FROM ledger GROUP BY method").fetchall()
    conn.close()

    click.echo(click.style("Ledger Statistics:\n", bold=True))
    headers = ["Metric", "Value"]
    stats_rows = [["Total entries", total], ["Unique users", users]]
    for m, c in methods:
        stats_rows.append([f"{m} requests", c])
    print_table(stats_rows, headers)


@cli.command()
@click.argument("db_path")
@click.confirmation_option(prompt="Are you sure you want to clear all logs?")
@require_auth("clear")
def clear(db_path):
    """Clear all log entries (admin only - use for testing only)."""
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM ledger")
    conn.commit()
    conn.close()
    click.echo(click.style("⚠️  Ledger cleared.", fg="red"))


@cli.command()
@click.argument("db_path")
@click.option("--interval", default=2.0, help="Seconds between refreshes")
@require_auth("watch")
def watch(db_path, interval):
    """Continuously watch new logs in real time (all roles)."""
    click.echo(click.style("Watching for new entries (Ctrl+C to stop)\n", fg="cyan", bold=True))
    last_count = 0
    while True:
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT ts, method, path, user, status FROM ledger ORDER BY ts ASC")
            rows = cur.fetchall()
            conn.close()

            if len(rows) > last_count:
                new_entries = rows[last_count:]
                headers = ["Timestamp", "Method", "Path", "User", "Status"]
                rows_for_table = [[r[0], r[1], r[2], r[3], r[4]] for r in new_entries]
                print_table(rows_for_table, headers)
                last_count = len(rows)
            time.sleep(interval)
        except KeyboardInterrupt:
            click.echo(click.style("\nStopped watching.", fg="yellow"))
            break


@cli.command()
@click.argument("db_path", default="audit_log.db")
@require_auth("init")
def init(db_path):
    """Initialize a new empty ledger database (admin only)."""
    if os.path.exists(db_path):
        click.echo(click.style("✗ Database already exists.", fg="red"))
        return
    conn = sqlite3.connect(db_path)
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
        prev_hash TEXT
    )
    """)
    conn.commit()
    conn.close()
    click.echo(click.style(f"✓ Initialized new ledger at {db_path}", fg="green"))


@cli.command()
@click.option("--limit", default=50, help="Number of recent CLI operations to show")
@require_auth("audit-logs")
def audit_logs(limit):
    """View CLI audit logs (admin only)."""
    if not os.path.exists(CLI_AUDIT_PATH):
        click.echo(click.style("No CLI audit logs found.", fg="yellow"))
        return
    
    conn = sqlite3.connect(CLI_AUDIT_PATH)
    rows = conn.execute(
        "SELECT timestamp, username, role, command, success, error FROM cli_audit ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    
    if not rows:
        click.echo(click.style("No CLI audit entries found.", fg="yellow"))
        return
    
    click.echo(click.style(f"Last {len(rows)} CLI operations:\n", bold=True))
    headers = ["Timestamp", "Username", "Role", "Command", "Success", "Error"]
    rows_for_table = []
    for r in rows:
        success_icon = "✓" if r[4] else "✗"
        success_colored = click.style(success_icon, fg="green" if r[4] else "red")
        rows_for_table.append([r[0], r[1], r[2], r[3], success_colored, r[5] or ""])
    print_table(rows_for_table, headers)


@cli.command()
def roles():
    """Display available roles and their permissions."""
    click.echo(click.style("Available Roles:\n", bold=True))
    
    for role_name, role_info in ROLES.items():
        click.echo(click.style(f"{role_name.upper()}", fg="cyan", bold=True))
        click.echo(f"  Description: {role_info['description']}")
        click.echo(f"  Permissions: {', '.join(role_info['permissions'])}")
        click.echo()


# ==================== Compliance Commands (Admin Only) ====================

@cli.command()
@click.argument("db_path")
@require_auth("verify")
def verify_enhanced(db_path):
    """Verify ledger with enhanced compliance checks (verifier, admin)."""
    try:
        from .ledger import verify_ledger as verify_enhanced_ledger
        
        click.echo(click.style("Running enhanced verification with compliance checks...\n", bold=True))
        result = verify_enhanced_ledger(db_path, check_signatures=True, check_worm=True)
        
        if result.get("verified"):
            click.echo(click.style("✓ Ledger verified successfully with all compliance checks!", fg="green"))
        else:
            click.echo(click.style("✗ Ledger verification FAILED", fg="red", bold=True))
        
        click.echo(f"\nTotal entries: {result.get('total_entries', 0)}")
        click.echo(f"Issues found: {result.get('issues', 0)}")
        
        if "signature_failures" in result:
            click.echo(f"Signature failures: {result.get('signature_failures', 0)}")
        
        if "worm_violations" in result:
            click.echo(f"WORM violations: {result.get('worm_violations', 0)}")
        
        if result.get("details"):
            click.echo(click.style("\nIssue Details:", fg="yellow"))
            for issue in result["details"][:10]:
                click.echo(f"  - Row {issue['row']}: {issue['reason']}")
    
    except ImportError:
        click.echo(click.style("Enhanced compliance modules not available.", fg="yellow"))
        click.echo("Install with: pip install cryptography")


@cli.command()
@click.argument("db_path")
@require_auth("admin")
def worm_status(db_path):
    """Show WORM protection status (admin only)."""
    try:
        from .worm import get_protection_stats, get_violations
        
        stats = get_protection_stats(db_path)
        
        click.echo(click.style("WORM Protection Status:\n", bold=True))
        click.echo(f"Protected entries: {stats['protected_entries']}")
        click.echo(f"Violations detected: {stats['violations_detected']}")
        click.echo(f"Integrity rate: {stats['integrity_rate']:.2f}%")
        
        violations = get_violations(db_path, limit=10)
        if violations:
            click.echo(click.style(f"\nRecent Violations ({len(violations)}):", fg="red", bold=True))
            headers = ["ID", "Entry Hash", "Type", "Detected At"]
            rows = [[v['id'], v['entry_hash'][:16] + '...', v['violation_type'], v['detected_at']] 
                    for v in violations[:10]]
            print_table(rows, headers)
    
    except ImportError:
        click.echo(click.style("WORM module not available.", fg="yellow"))


@cli.command()
@click.argument("db_path")
@require_auth("admin")
def enable_worm(db_path):
    """Enable WORM protection for all entries in a database (admin only)."""
    try:
        from .worm import enable_worm_for_database
        
        click.echo(click.style(f"Enabling WORM protection for {db_path}...", fg="cyan"))
        count = enable_worm_for_database(db_path)
        click.echo(click.style(f"✓ Protected {count} entries.", fg="green"))
    
    except ImportError:
        click.echo(click.style("WORM module not available.", fg="yellow"))


@cli.command()
@require_auth("admin")
def init_signing():
    """Initialize digital signature keys (admin only)."""
    try:
        from .signatures import initialize_signing_keys, get_key_metadata
        
        if get_key_metadata():
            click.echo(click.style("Signing keys already exist.", fg="yellow"))
            meta = get_key_metadata()
            click.echo(f"Created: {meta['created_at']}")
            click.echo(f"Key size: {meta['key_size']} bits")
            click.echo(f"Algorithm: {meta['algorithm']}")
        else:
            password = click.prompt("Enter password to encrypt private key (or leave empty)", 
                                   hide_input=True, default="", show_default=False)
            if password == "":
                password = None
            
            initialize_signing_keys(password=password, key_size=2048)
            click.echo(click.style("✓ Signing keys initialized successfully.", fg="green"))
            click.echo("Keys stored in: ~/.audittrail_keys/")
    
    except ImportError:
        click.echo(click.style("Signature module not available.", fg="yellow"))


@cli.command()
@click.option("--limit", default=50, help="Number of anomalies to show")
@click.option("--unresolved-only", is_flag=True, help="Show only unresolved anomalies")
@require_auth("admin")
def anomalies(limit, unresolved_only):
    """View detected anomalies (admin only)."""
    try:
        from .anomaly import get_recent_anomalies
        
        anomaly_list = get_recent_anomalies(limit=limit, unresolved_only=unresolved_only)
        
        if not anomaly_list:
            click.echo(click.style("No anomalies detected.", fg="green"))
            return
        
        click.echo(click.style(f"{'Unresolved ' if unresolved_only else ''}Anomalies ({len(anomaly_list)}):\n", bold=True))
        
        headers = ["ID", "Type", "Severity", "Detected At", "Description"]
        rows = [[a['id'], a['anomaly_type'], a['severity'], a['detected_at'], a['description'][:50]] 
                for a in anomaly_list]
        print_table(rows, headers)
    
    except ImportError:
        click.echo(click.style("Anomaly detection module not available.", fg="yellow"))


@cli.command()
@click.argument("anomaly_id", type=int)
@require_auth("admin")
def resolve_anomaly(anomaly_id):
    """Mark an anomaly as resolved (admin only)."""
    try:
        from .anomaly import resolve_anomaly as resolve_anomaly_fn
        
        resolve_anomaly_fn(anomaly_id)
        click.echo(click.style(f"✓ Anomaly {anomaly_id} marked as resolved.", fg="green"))
    
    except ImportError:
        click.echo(click.style("Anomaly detection module not available.", fg="yellow"))


@cli.command()
@click.argument("db_path")
@click.option("--output", default="compliance_report.json", help="Output file path")
@click.option("--format", type=click.Choice(["json", "html"]), default="json", help="Report format")
@require_auth("admin")
def compliance_report(db_path, output, format):
    """Generate comprehensive compliance report (admin only)."""
    try:
        from .compliance_report import generate_compliance_report, export_report_to_json, export_report_to_html
        
        click.echo(click.style("Generating compliance report...", fg="cyan"))
        report = generate_compliance_report(db_path)
        
        if format == "json":
            export_report_to_json(report, output)
        else:
            export_report_to_html(report, output)
        
        click.echo(click.style(f"✓ Report saved to: {output}", fg="green"))
        
        # Show summary
        summary = report.get('compliance_summary', {})
        click.echo(click.style(f"\nCompliance Status: {summary.get('overall_status', 'UNKNOWN')}", 
                              fg="green" if summary.get('overall_status') == 'COMPLIANT' else "red", bold=True))
        click.echo(f"Risk Level: {summary.get('risk_level', 'UNKNOWN')}")
    
    except ImportError:
        click.echo(click.style("Compliance report module not available.", fg="yellow"))


@cli.command()
@require_auth("admin")
def compliance_status():
    """Show overall compliance feature status (admin only)."""
    try:
        from .signatures import get_key_metadata
        from .timestamp import get_timestamp_statistics
        from .worm import get_protection_stats
        from .anomaly import get_anomaly_statistics, init_default_rules
        
        click.echo(click.style("Compliance Features Status:\n", bold=True))
        
        # Digital Signatures
        key_meta = get_key_metadata()
        if key_meta:
            click.echo(click.style("✓ Digital Signatures: ENABLED", fg="green"))
            click.echo(f"  Key size: {key_meta['key_size']} bits")
            click.echo(f"  Created: {key_meta['created_at']}")
        else:
            click.echo(click.style("✗ Digital Signatures: NOT INITIALIZED", fg="yellow"))
            click.echo("  Run: audittrail init-signing")
        
        # Timestamps
        ts_stats = get_timestamp_statistics()
        click.echo(click.style(f"\n✓ Timestamps: {ts_stats['total_timestamps']} entries timestamped", fg="green"))
        
        # WORM Protection
        worm_stats = get_protection_stats()
        click.echo(click.style(f"\n✓ WORM Protection: {worm_stats['protected_entries']} entries protected", fg="green"))
        click.echo(f"  Violations: {worm_stats['violations_detected']}")
        click.echo(f"  Integrity: {worm_stats['integrity_rate']:.1f}%")
        
        # Anomaly Detection
        init_default_rules()  # Ensure rules exist
        anomaly_stats = get_anomaly_statistics()
        click.echo(click.style(f"\n✓ Anomaly Detection: {anomaly_stats['total_anomalies']} anomalies detected", fg="green"))
        click.echo(f"  Unresolved: {anomaly_stats['unresolved']}")
        click.echo(f"  Last 24h: {anomaly_stats['last_24_hours']}")
        
    except ImportError as e:
        click.echo(click.style(f"Compliance modules not fully available: {str(e)}", fg="yellow"))
