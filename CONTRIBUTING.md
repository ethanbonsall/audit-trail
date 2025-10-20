# Contributing to audittrail-py

Thanks for your interest in contributing! 🎉
This project is open to community improvements, bug fixes, and new ideas.
We welcome contributions from developers of all experience levels.

---

## Getting Started

1. **Fork the repository**

   * Click “Fork” at the top right of this page to create your own copy.

2. **Clone your fork**

   ```bash
   git clone https://github.com/<your-username>/audittrail-py.git
   cd audittrail-py
   ```

3. **Create a new branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Install dependencies**

   ```bash
   pip install -e .[dev]
   ```

5. **Run the example app (optional)**

   ```bash
   uvicorn test_app:app --reload
   ```

---

## Code Guidelines

* Follow [PEP 8](https://peps.python.org/pep-0008/) style conventions.
* Keep functions short and readable.
* Use clear, descriptive names and add docstrings for public methods.
* Group related logic together logically — readability matters.
* Commit messages should be short and meaningful (e.g. `add CLI stats command`).

---

## Testing

We use `pytest` for testing.
If you add a new feature or fix a bug, please include corresponding tests.

```bash
pytest
```

Example structure:

```
tests/
 ├── test_ledger.py
 ├── test_middleware.py
 └── test_cli.py
```

---

## Pull Request Process

1. **Keep your branch up to date** with `main`:

   ```bash
   git fetch origin
   git merge origin/main
   ```

2. **Ensure all tests pass** before submitting:

   ```bash
   pytest
   flake8 audittrail
   ```

3. **Push your branch**:

   ```bash
   git push origin feature/your-feature-name
   ```

4. **Open a Pull Request**

   * Explain what you changed and why.
   * Link any related issues or feature requests.

---

## Feature Ideas

Here are some good ways to contribute:

### High Priority
* [ ] Add Flask & Django middleware support
* [ ] HSM/KMS integration for production key management
* [ ] External Timestamp Authority (RFC 3161) integration
* [ ] Webhook and email alert notifications
* [ ] Custom backend adapters (PostgreSQL, MongoDB)

### Medium Priority
* [ ] Build a web dashboard for visualizing logs
* [ ] Add field-level encryption and redaction options
* [ ] Multi-tenant support with tenant isolation
* [ ] Automated compliance report scheduling
* [ ] Integration with SIEM systems
* [ ] Performance benchmarking and optimization

### Nice to Have
* [ ] Add integration with Python's built-in `logging` module
* [ ] GraphQL API for audit log queries
* [ ] Blockchain anchoring for ultimate immutability
* [ ] Machine learning for advanced anomaly detection

---

## Production Readiness Status

### Completed Security Improvements

These critical security features have been **implemented** and are production-ready:

- **Hash Verification** — Standardized hash computation across all components
- **Access Controls** — Role-based access control (Viewer, Verifier, Admin) with CLI audit logging
- **Compliance Features** — Digital signatures, timestamps, WORM protection, and anomaly detection
- **Encrypted Payloads** — Request/response bodies encrypted at rest
- **CLI Audit Trail** — All CLI operations logged with user/role tracking

### Production Considerations

Before deploying to production (especially for financial/enterprise use), consider these enhancements:

#### 1. Enhanced Key Management
- **Current:** Encryption keys and signing keys stored locally with file permissions (0600)
- **Recommended:** Integrate with Hardware Security Module (HSM) or cloud KMS (AWS KMS, Azure Key Vault, GCP KMS)
- **Action:** Add support for external key management and key rotation

#### 2. Advanced User Identification
- **Current:** User logged as client IP address
- **Recommended:** Integrate with your authentication system
- **Action:** Extract user ID from JWT tokens, OAuth headers, or session data in your application layer

#### 3. External Timestamp Authority
- **Current:** Local trusted timestamps (cryptographically secure but self-signed)
- **Recommended:** Integrate with external RFC 3161 Timestamp Authority for legal validity
- **Action:** Configure external TSA service (DigiCert, GlobalSign, etc.)

#### 4. Testing & Validation
- **Current:** Basic functionality tested
- **Recommended:** Comprehensive test suite for security-critical components
- **Action:** Add integration tests for verification pipeline, encryption, signatures, and WORM integrity

#### 5. Alert Delivery
- **Current:** Anomalies logged to database
- **Recommended:** Active notification system
- **Action:** Implement webhook/email alert delivery for critical anomalies

---

> **Note:** The core audit trail is **production-ready** with bank-grade security features. The items above are **enhancements** for specific enterprise requirements.

---

## 🧾 License

By contributing, you agree that your contributions will be licensed under the same license as this project (MIT).

---

## Thank You

Your help makes `audittrail-py` better for everyone!
If you’re unsure where to start, feel free to open an issue — we’ll help you find something approachable.
Maintainer: [Ethan P. Bonsall](https://github.com/ethanbonsall)
