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

* [ ] Add Flask & Django middleware support
* [ ] Add CLI commands like `audittrail tail` or `audittrail summary`
* [ ] Add data encryption or field redaction options
* [ ] Improve verification reporting (JSON output with root hash)
* [ ] Add integration with Python’s built-in `logging` module
* [ ] Build a simple dashboard for visualizing logs

---
# Known Issues / Security To-Dos

These items are **critical to fix before production** use, especially for financial or enterprise environments.

---

## 1. Fix Hash Verification Inconsistency

- `middleware.py`, `ledger.py (add_entry)`, and `ledger.py (verify_ledger)` use **different string/hash formats**.  
- **Action:** Standardize the hash computation format and field order so that verification passes consistently across all components.

---

## 2. Improve Key Management

- The encryption key is currently stored in plaintext (`~/.audittrail.key`).  
- **Action Items:**
  - Implement secure key storage (e.g., **AWS KMS**, **GCP KMS**, or a password-protected keyring).  
  - Add support for **key rotation** and **per-environment keys**.

---

## 3. Strengthen User Identification

- Currently, logs only use the client IP address as the user identifier.  
- **Action Items:**
  - Integrate proper authentication systems such as **JWT tokens**, **OAuth user IDs**, or **session identifiers**.  
  - Ensure logged user information matches authenticated entities.

---

## 4. Add Access Controls

- Anyone can currently verify or export logs using the CLI.  
- **Action Items:**
  - Restrict sensitive commands to authorized roles.  
  - Implement **role-based permissions** and **audit logging** for CLI operations.

---

## 5. Compliance & Integrity Features

- Add advanced integrity and compliance mechanisms.  
- **Action Items:**
  - Introduce **digital signatures**, **timestamp authorities**, and **immutable (WORM) storage**.  
  - Build **alerting or anomaly detection** for suspected tampering events.

---

## 6. Testing Enhancements

- Current test coverage is insufficient for security-critical components.  
- **Action Items:**
  - Add **integration tests** for the hashing and verification pipeline.  
  - Include tests for **encrypted/decrypted audit log validation**.

---

> **Note:** These improvements are essential for transforming this project from a learning/demo tool into a **production-ready, auditable, and compliant system**.

---

## 🧾 License

By contributing, you agree that your contributions will be licensed under the same license as this project (MIT).

---

## 🙌 Thank You

Your help makes `audittrail-py` better for everyone!
If you’re unsure where to start, feel free to open an issue — we’ll help you find something approachable.
Maintainer: [Ethan P. Bonsall](https://github.com/ethanbonsall)
