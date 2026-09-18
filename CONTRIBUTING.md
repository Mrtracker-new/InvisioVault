# Contributing to InvisioVault

Thank you for your interest in contributing to InvisioVault! I welcome contributions that improve security, performance, accessibility, documentation, and user experience.

---

## 1. Code of Conduct

I am committed to providing a welcoming, respectful, and harassment-free experience for everyone. Please treat all contributors with courtesy, respect, and constructive professionalism.

---

## 2. Getting Started

### Prerequisites
- **Python:** 3.10 or higher
- **Node.js:** 18 or higher (with npm v9+)
- **Git**

### Local Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Mrtracker-new/InvisioVault.git
   cd InvisioVault
   ```

2. **Windows Fast Setup:**
   Run `run.bat` — this will activate the Python virtual environment, boot the Flask backend on port 5000, and launch the Vite development server with HTTPS on port 5173.

3. **Manual Setup:**
   * **Backend:**
     ```bash
     cd backend
     python -m venv .venv
     # Windows:
     .venv\Scripts\activate
     # Linux/macOS:
     source .venv/bin/activate
     pip install -r requirements.txt
     python app.py
     ```
   * **Frontend:**
     ```bash
     cd frontend
     npm install
     npm run dev
     ```

---

## 3. Development Guidelines

### Cryptography & Security First
- **Zero Inventions:** Never implement custom or non-standard cryptographic primitives. Always rely on vetted primitives from `cryptography.fernet`, `hashlib.pbkdf2_hmac`, or `reedsolo`.
- **Constant-Time Verification:** Ensure password and MAC comparisons use constant-time operations (`hmac.compare_digest`).
- **Memory & File Cleanup:** Any operation touching the filesystem must register cleanup inside a `finally` block or context manager.
- **Resource Constraints:** The production backend runs in a 512 MB memory envelope on Render. Avoid holding unbounded raw file arrays in memory; prefer streaming, chunked iterations, or `mmap`.

### Coding Standards
- **Python:**
  - Follow PEP 8 guidelines.
  - Include type annotations (`from typing import Optional, Tuple, List`).
  - Write descriptive docstrings for all exported functions and routes.
- **Frontend (React/CSS):**
  - Use semantic HTML elements and maintain WCAG 2.1 AA accessibility (ARIA roles, keyboard navigation, focus visible rings).
  - Use design tokens from `variables.css`. Avoid arbitrary inline magic colors.
  - Run linting before committing:
    ```bash
    npm run lint
    ```

---

## 4. Testing Your Changes

Before submitting a pull request, ensure all unit, integration, and security tests pass:

### Running Backend Tests
```bash
cd backend
python -m pytest tests/test_integration.py -v
python -m pytest tests/test_concurrency.py -v
python -m pytest tests/test_camera_scan.py -v
python -m pytest tests/test_differential_ecc.py -v
python -m pytest tests/test_memory_recovery.py -v
```

### Running Frontend Tests & Build Validation
```bash
cd frontend
npm run lint
npm run build
```

---

## 5. Submitting a Pull Request (PR)

1. Create a descriptive feature branch:
   ```bash
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/your-bug-fix
   ```
2. Commit your changes with clear, semantic commit messages:
   ```bash
   git commit -m "feat(qr): add local client-side payload parsing fallback"
   ```
3. Push your branch and open a Pull Request against `main`.
4. Provide a thorough PR description outlining what changed, why it was needed, and how it was verified.
