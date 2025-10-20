# audittrail

**audittrail** is a lightweight, open-source Python library for creating a **tamper-proof audit trail** of API activity. It works as a plug-and-play middleware for FastAPI (and soon Flask/Django), automatically recording each request and cryptographically linking entries to prevent undetected tampering.

---

## Features

- **Tamper-proof logging** — Each log entry is hashed and chained to the previous one.
- **Plug-and-play middleware** — Just import and add it to your FastAPI app.
- **Verifiable ledger** — Easily confirm the integrity of your audit log.
- **Lightweight storage** — Uses a simple SQLite backend by default.
- **Framework-agnostic** — Middleware ready for FastAPI; extensible for Flask or Django.

---

## Installation

```bash
pip install audittrail
```

or from source:

```bash
git clone https://github.com/ethanbonsall/audittrail-py.git
cd audittrail-py
pip install .
```

---

## ⚡ Quick Start (FastAPI Example)

```python
from fastapi import FastAPI
from audittrail import AuditTrailMiddleware, verify_ledger

app = FastAPI()
app.add_middleware(AuditTrailMiddleware, storage_path="audit_log.db")

@app.post("/create")
def create_item(item: dict):
    return {"msg": "created", "item": item}

# Verify the integrity of the log manually
print(verify_ledger("audit_log.db"))
```

Every incoming request is logged in `audit_log.db` with a cryptographic hash linking it to the previous entry.

---

## Example Log Entry

| ts | method | path | user | status | hash | prev_hash |
|----|---------|------|------|---------|------|------------|
| 2025-10-19T22:01Z | POST | /create | anonymous | 201 | `a8f92d...` | `1cd32a...` |

---

## Verify Ledger Integrity

You can verify the entire log chain to ensure no tampering:

```python
from audittrail import verify_ledger

result = verify_ledger("audit_log.db")
print(result)  # {"verified": True, "entries": 128}
```

If any record was altered, the verification will fail and return:

```json
{"verified": false, "error_at": "2025-10-19T21:52:00Z"}
```

---

## Directory Structure

```
audittrail/
├── __init__.py
├── middleware.py        # FastAPI middleware to capture requests
├── ledger.py            # Core ledger logic (hashing, verify)
├── storage.py (planned) # Optional modular backend adapter
├── cli.py (planned)     # Command-line verification tool
setup.py
README.md
```

---

## Roadmap
- [ ] Flask & Django middleware support
- [ ] Encrypted payload logging
- [ ] CLI tool (`audittrail verify`)
- [ ] Custom backends (PostgreSQL, JSON file, etc.)

---

## 🧑Contributing
Contributions are welcome! Fork the repo, create a feature branch, and open a PR.

```bash
git checkout -b feature/add-flask-support
git commit -m "Add Flask middleware"
git push origin feature/add-flask-support
```

---

## 📄 License
MIT License © 2025 Ethan P. Bonsall

---

### Summary
**audittrail** lets you easily add cryptographically verifiable logging to your API — a practical, production-ready project that brings transparency, security, and developer trust to any backend system.
