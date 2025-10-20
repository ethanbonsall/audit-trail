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

## 🧾 License

By contributing, you agree that your contributions will be licensed under the same license as this project (MIT).

---

## 🙌 Thank You

Your help makes `audittrail-py` better for everyone!
If you’re unsure where to start, feel free to open an issue — we’ll help you find something approachable.
Maintainer: [Ethan P. Bonsall](https://github.com/ethanbonsall)
