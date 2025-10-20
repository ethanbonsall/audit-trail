# Role-Based Access Control (RBAC) Guide

## Overview

AuditTrail CLI now features comprehensive role-based access control (RBAC) with three distinct roles, user authentication, and CLI audit logging. This ensures that only authorized users can access sensitive audit data and administrative functions.

---

## Roles and Permissions

### 🔵 Viewer
**Description:** Can view encrypted logs  
**Permissions:**
- `logs` - View audit logs (encrypted)
- `search` - Search through logs
- `stats` - View statistics
- `watch` - Watch logs in real-time

**Use Case:** For general users who need to monitor system activity but don't need to verify integrity or see decrypted data.

---

### 🟢 Verifier
**Description:** Can verify logs and view encrypted logs  
**Permissions:**
- All viewer permissions, plus:
- `verify` - Verify ledger integrity
- `export` - Export logs to JSON/CSV

**Use Case:** For auditors and compliance officers who need to verify data integrity but don't need administrative access or decryption.

---

### 🔴 Admin
**Description:** Full access including decryption and user management  
**Permissions:**
- All verifier permissions, plus:
- `decrypt` - Decrypt request/response bodies in logs
- `clear` - Clear all logs (testing only)
- `init` - Initialize new ledger databases
- `add-user` - Create new users
- `list-users` - View all users
- `remove-user` - Delete users
- `audit-logs` - View CLI audit trail

**Use Case:** For system administrators and security teams who need full access to all audit trail functionality.

---

## Getting Started

### First-Time Setup

On first run, AuditTrail automatically creates a default admin user:

```bash
audittrail roles
```

**Default Credentials:**
- Username: `admin`
- Password: `admin`

⚠️ **IMPORTANT:** Change the default password immediately after first login!

---

## Authentication Commands

### Login
```bash
audittrail login
# You'll be prompted for username and password
```

### Check Current Session
```bash
audittrail whoami
```

Output:
```
Username: admin
Role: admin
Permissions: logs, search, stats, watch, verify, export, decrypt, clear, init, add-user, list-users, remove-user, audit-logs
Session created: 2025-10-20T15:26:49.731223
```

### Change Your Password
```bash
audittrail change-password
# You'll be prompted for current and new password
```

### Logout
```bash
audittrail logout
```

### View Available Roles
```bash
audittrail roles
```

---

## User Management (Admin Only)

### Add a New User
```bash
audittrail add-user
# Interactive prompts for: username, password, role
```

Or with options:
```bash
audittrail add-user --username john --password secret123 --role viewer
```

### List All Users
```bash
audittrail list-users
```

Example output:
```
╒═══════════════╤══════════╤════════════════════════════════╕
│ Username      │ Role     │ Created At                     │
╞═══════════════╪══════════╪════════════════════════════════╡
│ admin         │ admin    │ 2025-10-20T19:26:35.029901+00  │
│ viewer_user   │ viewer   │ 2025-10-20T19:27:01.711121+00  │
│ verifier_user │ verifier │ 2025-10-20T19:27:07.195521+00  │
╘═══════════════╧══════════╧════════════════════════════════╛
```

### Remove a User
```bash
audittrail remove-user <username>
# Confirmation prompt will appear
```

**Safety:** Cannot remove the last admin user.

---

## Working with Audit Logs

### View Logs (All Roles)
```bash
# View recent logs (encrypted)
audittrail logs audit_log.db --limit 10

# View with decryption (admin only)
audittrail logs audit_log.db --limit 10 --decrypt
```

### Verify Ledger Integrity (Verifier, Admin)
```bash
audittrail verify audit_log.db
```

Success:
```
✓ Ledger verified successfully — no tampering detected.
```

Failure:
```
✗ Ledger verification FAILED
  - Row 2: Hash mismatch
```

### Search Logs (All Roles)
```bash
# Search by user
audittrail search audit_log.db --user 127.0.0.1

# Search by endpoint path
audittrail search audit_log.db --path /deposit

# Combine filters
audittrail search audit_log.db --user john --path /api
```

### View Statistics (All Roles)
```bash
audittrail stats audit_log.db
```

### Export Logs (Verifier, Admin)
```bash
# Export to JSON
audittrail export audit_log.db --format json --out backup.json

# Export to CSV
audittrail export audit_log.db --format csv --out backup.csv
```

### Watch Logs in Real-Time (All Roles)
```bash
audittrail watch audit_log.db --interval 2
# Press Ctrl+C to stop
```

---

## CLI Audit Trail

### View CLI Operations (Admin Only)
```bash
audittrail audit-logs --limit 20
```

This shows all CLI operations including:
- Who executed each command
- Their role at the time
- Success/failure status
- Error messages for failed operations
- Timestamps

Example output:
```
╒════════════════════╤═══════════════╤══════════╤════════════╤═══════════╤════════════════════╕
│ Timestamp          │ Username      │ Role     │ Command    │ Success   │ Error              │
╞════════════════════╪═══════════════╪══════════╪════════════╪═══════════╪════════════════════╡
│ 2025-10-20T19:29   │ viewer_user   │ viewer   │ verify     │ ✗         │ Permission denied  │
│ 2025-10-20T19:28   │ viewer_user   │ viewer   │ logs       │ ✓         │                    │
│ 2025-10-20T19:27   │ admin         │ admin    │ add-user   │ ✓         │                    │
╘════════════════════╧═══════════════╧══════════╧════════════╧═══════════╧════════════════════╛
```

---

## Security Features

### 1. Password Security
- Passwords are hashed using PBKDF2-HMAC-SHA256 with random salts
- 100,000 iterations for key derivation
- Never stored in plaintext

### 2. Session Management
- Sessions expire after 24 hours
- Session data stored securely in user's home directory
- File permissions set to 0600 (owner read/write only)

### 3. Audit Trail
- All CLI operations are logged with username, role, and timestamp
- Failed authentication attempts are tracked
- Permission denials are recorded

### 4. File Security
- User database: `~/.audittrail_users.json` (0600 permissions)
- Session file: `~/.audittrail_session.json` (0600 permissions)
- CLI audit log: `~/.audittrail_cli_audit.db`

---

## Permission Boundaries

### What Each Role Can Do

| Command        | Viewer | Verifier | Admin |
|----------------|--------|----------|-------|
| login          | ✓      | ✓        | ✓     |
| logout         | ✓      | ✓        | ✓     |
| whoami         | ✓      | ✓        | ✓     |
| change-password| ✓      | ✓        | ✓     |
| roles          | ✓      | ✓        | ✓     |
| logs           | ✓      | ✓        | ✓     |
| search         | ✓      | ✓        | ✓     |
| stats          | ✓      | ✓        | ✓     |
| watch          | ✓      | ✓        | ✓     |
| verify         | ✗      | ✓        | ✓     |
| export         | ✗      | ✓        | ✓     |
| logs --decrypt | ✗      | ✗        | ✓     |
| add-user       | ✗      | ✗        | ✓     |
| remove-user    | ✗      | ✗        | ✓     |
| list-users     | ✗      | ✗        | ✓     |
| clear          | ✗      | ✗        | ✓     |
| init           | ✗      | ✗        | ✓     |
| audit-logs     | ✗      | ✗        | ✓     |

---

## Best Practices

### 1. Initial Setup
```bash
# Change default admin password immediately
audittrail login  # Use admin/admin
audittrail change-password
```

### 2. Create Role-Specific Users
```bash
# For developers who need to monitor logs
audittrail add-user --username dev1 --role viewer

# For auditors who need to verify integrity
audittrail add-user --username auditor1 --role verifier

# For security team members
audittrail add-user --username security1 --role admin
```

### 3. Regular Security Audits
```bash
# Review who has access
audittrail list-users

# Check CLI operations
audittrail audit-logs --limit 100
```

### 4. Least Privilege Principle
- Grant the minimum role needed for each user's job function
- Regularly review user permissions
- Remove users who no longer need access

### 5. Monitor Failed Access Attempts
```bash
# Check for suspicious activity in CLI audit logs
audittrail audit-logs | grep "Permission denied"
```

---

## Troubleshooting

### "Authentication required. Please login first."
You need to authenticate before using most commands:
```bash
audittrail login
```

### "Permission denied. Your role 'X' cannot execute 'Y'."
Your role doesn't have permission for this command. Contact your administrator or check permissions:
```bash
audittrail roles
audittrail whoami
```

### Session Expired
Sessions expire after 24 hours. Simply login again:
```bash
audittrail login
```

### Forgot Password
Contact an administrator to reset your account:
```bash
audittrail remove-user <username>
audittrail add-user  # Recreate with new password
```

---

## Integration Example

### For Banking Applications

```bash
# 1. Setup admin account
audittrail login
audittrail change-password

# 2. Create compliance officer account
audittrail add-user --username compliance_officer --role verifier

# 3. Create developer monitoring account
audittrail add-user --username dev_monitor --role viewer

# 4. Create security team admin
audittrail add-user --username security_admin --role admin

# 5. Regular verification (compliance officer)
audittrail verify bank_audit_log.db

# 6. Export for regulators (compliance officer)
audittrail export bank_audit_log.db --format csv --out quarterly_report.csv

# 7. Review CLI operations (admin)
audittrail audit-logs --limit 500 > cli_audit_report.txt
```

---

## Architecture

### Authentication Flow
```
User runs command
    ↓
Check for active session (~/.audittrail_session.json)
    ↓
If no session → prompt "Please login first"
    ↓
If session exists → verify not expired (24h)
    ↓
Check user's role permissions
    ↓
If authorized → execute command + log to CLI audit
    ↓
If unauthorized → deny + log failed attempt
```

### Security Layers
1. **Authentication:** Username/password verification
2. **Authorization:** Role-based permission checking
3. **Audit:** All operations logged to CLI audit trail
4. **Encryption:** Request/response bodies encrypted (admin-only decryption)
5. **File Permissions:** Restricted access to config files (0600)

---

## Files Created by RBAC System

- `~/.audittrail_users.json` - User credentials and roles
- `~/.audittrail_session.json` - Current session data
- `~/.audittrail_cli_audit.db` - CLI operations audit trail
- `~/.audittrail.key` - Encryption key (pre-existing)

All files are stored in the user's home directory with restricted permissions.

---

## Summary

The RBAC system provides:
- ✅ Three well-defined roles (viewer, verifier, admin)
- ✅ Secure password storage with PBKDF2
- ✅ Session management with auto-expiry
- ✅ Comprehensive CLI audit logging
- ✅ Granular permission control
- ✅ Protection against unauthorized access
- ✅ Compliance-ready audit trails

This makes AuditTrail suitable for production environments where access control and accountability are critical requirements.

