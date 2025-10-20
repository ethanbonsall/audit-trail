import click
import sqlite3
import json
import csv
import time
import os
from .ledger import verify_ledger
from cryptography.fernet import Fernet
import os
from tabulate import tabulate



KEY_PATH = os.path.expanduser("~/.audittrail.key")

def load_cipher():
    if not os.path.exists(KEY_PATH):
        raise click.ClickException("Encryption key not found. Run your API once to generate ~/.audittrail.key.")
    with open(KEY_PATH, "rb") as f:
        return Fernet(f.read())


def print_table(rows, headers):
    """Pretty print rows using tabulate."""
    clean_rows = [[click.unstyle(str(item)) for item in row] for row in rows]

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


@click.group()
def cli():
    """AuditTrail CLI — Verify, inspect, and manage audit logs."""
    pass


@cli.command()
@click.argument("db_path")
def verify(db_path):
    """Verify the integrity of the ledger and show where tampering occurred."""
    result = verify_ledger(db_path)
    if result.get("verified"):
        click.echo(click.style("Ledger verified successfully — no tampering detected.", fg="green"))
    else:
        click.echo(click.style("Ledger verification FAILED", fg="red", bold=True))
        if "details" in result:
            for issue in result["details"]:
                click.echo(click.style(f"- Row {issue['row']}: {issue['reason']}", fg="yellow"))
        else:
            click.echo(click.style(f"Reason: {result.get('error', 'Unknown error')}", fg="yellow"))

@cli.command()
@click.argument("db_path")
@click.option("--limit", default=10, help="Number of recent entries to show")
def logs(db_path, limit):
    """Show recent log entries."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT ts, method, path, user, status FROM ledger ORDER BY ts DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()

    click.echo(click.style(f"Last {len(rows)} log entries:\n", bold=True))
    headers = ["Timestamp", "Method", "Path", "User", "Status"]
    rows_for_table = [[r[0], r[1], r[2], r[3], r[4]] for r in rows]
    print_table(rows_for_table, headers)


@cli.command()
@click.argument("db_path")
@click.option("--user", help="Filter by user")
@click.option("--path", help="Filter by endpoint path")
def search(db_path, user, path):
    """Search entries by user or endpoint."""
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
def export(db_path, format, out):
    """Export all logs to JSON or CSV."""
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
    click.echo(click.style(f"Exported {len(rows)} entries to {out}", fg="green"))


@cli.command()
@click.argument("db_path")
def stats(db_path):
    """Show simple ledger statistics."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
    users = cur.execute("SELECT COUNT(DISTINCT user) FROM ledger").fetchone()[0]
    methods = cur.execute("SELECT method, COUNT(*) FROM ledger GROUP BY method").fetchall()
    conn.close()

    click.echo(click.style("Ledger Statistics:\n"))
    headers = ["Metric", "Value"]
    stats_rows = [["Total entries", total], ["Unique users", users]]
    for m, c in methods:
        stats_rows.append([f"{m} requests", c])
    print_table(stats_rows, headers)


@cli.command()
@click.argument("db_path")
@click.confirmation_option(prompt="Are you sure you want to clear all logs?")
def clear(db_path):
    """Clear all log entries (use for testing only)."""
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM ledger")
    conn.commit()
    conn.close()
    click.echo(click.style("Ledger cleared.", fg="red"))


@cli.command()
@click.argument("db_path")
@click.option("--interval", default=2.0, help="Seconds between refreshes")
def watch(db_path, interval):
    """Continuously watch new logs in real time."""
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


CONFIG_PATH = os.path.expanduser("~/.audittrail.json")


@cli.command()
@click.argument("db_path", default="audit_log.db")
def init(db_path):
    """Initialize a new empty ledger database."""
    if os.path.exists(db_path):
        click.echo(click.style("Database already exists.", fg="red"))
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
    click.echo(click.style(f"Initialized new ledger at {db_path}", fg="green"))


@cli.command()
@click.option("--set-default", "default_path", help="Set default database path")
def config(default_path):
    """View or set CLI configuration."""
    if default_path:
        with open(CONFIG_PATH, "w") as f:
            json.dump({"default_path": default_path}, f)
        click.echo(click.style(f"Default DB set to {default_path}", fg="green"))
    elif os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        click.echo(click.style(f"Current config: {data}", fg="cyan"))
    else:
        click.echo(click.style("No config file found.", fg="yellow"))

@cli.command()
@click.argument("db_path")
@click.option("--limit", default=10, help="Number of recent entries to show")
@click.option("--decrypt", is_flag=True, help="Decrypt and show request/response bodies")
def logs(db_path, limit, decrypt):
    """Show recent log entries (optionally decrypted)."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT ts, method, path, user, status, body, response FROM ledger ORDER BY ts DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()

    headers = ["Timestamp", "Method", "Path", "User", "Status", "Request Body", "Response"]
    print_table(rows, headers)

    if decrypt:
        cipher = load_cipher()
        headers += ["Request Body", "Response"]
        rows_for_table = []
        for r in rows:
            dec_body = cipher.decrypt(r[5].encode()).decode(errors="ignore") if r[5] else ""
            dec_resp = cipher.decrypt(r[6].encode()).decode(errors="ignore") if r[6] else ""
            rows_for_table.append([r[0], r[1], r[2], r[3], r[4], dec_body, dec_resp])
    else:
        rows_for_table = [[r[0], r[1], r[2], r[3], r[4]] for r in rows]

    print_table(rows_for_table, headers)
