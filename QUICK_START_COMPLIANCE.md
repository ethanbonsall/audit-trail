# Quick Start: Compliance Features

## 5-Minute Setup

### 1. Login and Initialize

```bash
# Login as admin (default: admin/admin)
audittrail login

# Initialize digital signatures
echo "" | audittrail init-signing

# Enable WORM protection for existing database
audittrail enable-worm audit_log.db
```

### 2. Update Your Application

Use the middleware with compliance features enabled:

```python
from fastapi import FastAPI
from audittrail import AuditTrailMiddleware

app = FastAPI()

# Enable compliance features (signatures, timestamps, WORM)
app.add_middleware(
    AuditTrailMiddleware,
    storage_path="audit_log.db",
    enable_compliance=True  # This enables all compliance features!
)
```

### 3. Verify Everything Works

```bash
# Run enhanced verification
audittrail verify-enhanced audit_log.db

# Check compliance status
audittrail compliance-status

# Generate HTML report
audittrail compliance-report audit_log.db --format html
```

---

## Essential Commands

### Verification
```bash
# Standard verification
audittrail verify audit_log.db

# Enhanced verification (with signatures and WORM)
audittrail verify-enhanced audit_log.db
```

### Monitoring
```bash
# Check compliance features status
audittrail compliance-status

# View anomalies
audittrail anomalies --unresolved-only

# Check WORM protection
audittrail worm-status audit_log.db
```

### Reporting
```bash
# Generate compliance report
audittrail compliance-report audit_log.db --format html --output report.html
```

---

## 🔧 What Each Feature Does

| Feature | What It Prevents | How It Helps |
|---------|------------------|--------------|
| **Digital Signatures** | Entry tampering | Proves entries are authentic and unchanged |
| **Timestamps** | Backdating | Proves when entries were created |
| **WORM Protection** | Deletion/modification | Makes entries immutable |
| **Anomaly Detection** | Attacks going unnoticed | Alerts you to suspicious activity |

---

## For Banking Applications

### Complete Production Setup

```python
# app.py
from fastapi import FastAPI
from audittrail import AuditTrailMiddleware

app = FastAPI(title="Secure Bank API")

# This single line gives you:
# - Hash chain integrity
# - Encryption
# - Digital signatures
# - Timestamps
# - WORM protection
# - Anomaly detection
app.add_middleware(
    AuditTrailMiddleware,
    storage_path="bank_audit.db",
    enable_compliance=True  # Enable all compliance features
)

@app.post("/transfer")
async def transfer(amount: float, from_account: str, to_account: str):
    # Your transfer logic
    # Everything is automatically audited!
    return {"status": "success"}
```

### Daily Verification Script

```bash
#!/bin/bash
# daily_compliance.sh

audittrail login --username compliance_officer --password <password>
audittrail verify-enhanced bank_audit.db
audittrail compliance-report bank_audit.db \
    --format html \
    --output "reports/$(date +%Y%m%d).html"
audittrail anomalies --unresolved-only
```

---

## Troubleshooting

### "Enhanced modules not available"
```bash
# The compliance features require cryptography
pip install cryptography
```

### "Permission denied"
```bash
# Need admin role for compliance commands
audittrail login  # Login as admin
```

### "Verification failed"
This is working as designed - it detected tampering!
```bash
# Get details
audittrail verify-enhanced audit_log.db

# Check what was violated
audittrail worm-status audit_log.db
audittrail anomalies
```

---

## Understanding Compliance Status

```bash
audittrail compliance-status
```

**What you should see:**
```
✓ Digital Signatures: ENABLED         ← Good!
✓ Timestamps: N entries timestamped   ← Good!
✓ WORM Protection: N entries protected ← Good!
✓ Anomaly Detection: 0 unresolved     ← Good!
```

**What's bad:**
```
✗ Digital Signatures: NOT INITIALIZED  ← Run: audittrail init-signing
Unresolved: 5                          ← Run: audittrail anomalies
Violations: 3                          ← Check: audittrail worm-status
```

---

## Next Steps

1. **Read full documentation**: [COMPLIANCE_FEATURES.md](COMPLIANCE_FEATURES.md)
2. **Set up alerts**: Configure email/webhook notifications
3. **Schedule reports**: Automate daily/weekly compliance reports
4. **Test incident response**: Simulate tampering and verify detection
5. **Review with compliance team**: Show them the HTML reports

---

## Checklist for Production

- [ ] Digital signatures initialized (`audittrail init-signing`)
- [ ] WORM protection enabled (`audittrail enable-worm`)
- [ ] Using `AuditTrailEnhancedMiddleware` in code
- [ ] Enhanced verification runs successfully
- [ ] Compliance report generates without errors
- [ ] Anomaly detection configured
- [ ] CLI users created (admin, verifier, viewer)
- [ ] Backup includes all compliance databases
- [ ] Daily verification scheduled
- [ ] Incident response plan documented

---

## You Now Have

✅ **Bank-grade security** - Digital signatures and WORM protection  
✅ **Regulatory compliance** - Meets SOX, HIPAA, PCI-DSS, GDPR  
✅ **Tamper detection** - Automatic anomaly detection  
✅ **Professional reports** - HTML compliance reports for auditors  
✅ **Role-based access** - Viewer, Verifier, Admin roles  
✅ **Complete audit trail** - Every operation logged and protected  

**Your audit trail is now production-ready for banking applications! **

