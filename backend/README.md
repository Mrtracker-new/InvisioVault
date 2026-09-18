# InvisioVault Backend Service

The stateless cryptographic backend for InvisioVault. Implemented with Python 3.10+, Flask, Pillow, Cryptography, Segno, and ZXing-C++.

---

## 1. Directory Structure

```
backend/
├── api/
│   └── routes.py              # Blueprint declaring all 14 REST endpoints
├── config/
│   └── settings.py            # Environment configuration & CORS origin validation
├── utils/
│   ├── crypto_utils.py        # PBKDF2 key derivation & Fernet symmetric cryptography
│   ├── steganography.py       # Sobel edge filter, LSB matching & wire format encoders
│   ├── polyglot.py            # Dual-format binary concatenation & ZIP offset patching
│   ├── qr_stego.py            # QR steganography (Visual & Stream modes)
│   ├── qr_module_map.py       # Structural module isolation & masking
│   ├── validators.py          # Magic-byte file validation & dimension limits
│   └── cleanup.py             # Background ephemeral file cleaner thread
├── tests/                     # Comprehensive test suites
│   ├── test_integration.py    # End-to-end API route tests
│   ├── test_concurrency.py    # Render concurrency & semaphore benchmarks
│   ├── test_camera_scan.py    # Camera frame decode & cache hit tests
│   ├── test_differential_ecc.py # Reed-Solomon error correction tests
│   └── test_memory_recovery.py # Memory footprint & leak validation
├── app.py                     # Flask application factory & security headers
├── extensions.py              # Centralized Flask-Limiter instance
├── gunicorn.conf.py           # Production Gunicorn configuration & post_fork hook
└── requirements.txt           # Frozen Python dependencies
```

---

## 2. Environment Configuration

Create a `.env` file in the `backend/` directory based on `.env.example`:

```ini
# Flask & Server Core
FLASK_ENV=production
DEBUG=False
PORT=5000
# Generate with: python -c 'import secrets; print(secrets.token_hex(32))'
SECRET_KEY=your_64_character_secret_key_here

# Storage, Limits & Ephemeral Cleanup
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=52428800     # 50 MB default (hard safety capped at 100 MB in code)
MAX_PIXEL_COUNT=25000000        # 25 Megapixel cap for Pillow decompression bomb guard
SMALL_OBJECT_THRESHOLD_BYTES=1048576 # 1 MB threshold for zero-copy vs disk streaming
FILE_MAX_AGE_HOURS=1            # Ephemeral file scavenger retention (hours)
CLEANUP_INTERVAL_MINUTES=10     # Ephemeral file cleanup interval (minutes)

# Rate Limiting & Proxy
REDIS_URL=memory://             # Redis URI for distributed limits (memory:// for local)
BEHIND_PROXY=True               # Enables ProxyFix for Render/Cloudflare headers

# Security & CORS
# Comma-separated list of allowed origins (no trailing slashes, no wildcards)
CORS_ORIGINS=https://invisio-vault.vercel.app,http://localhost:5173

# Logging
LOG_LEVEL=INFO
LOG_FILE=app.log
```

---

## 3. Production Architecture (Render 512 MB Constraints)

The backend is configured for extreme memory efficiency and resilience under Render's free tier memory limit (512 MB):

1. **Gunicorn Worker Architecture (`gunicorn.conf.py`):**
   - Runs with 1 sync worker and 2 threads.
   - `post_fork` hook initializes the `FileCleanupScheduler` daemon safely inside the child worker process, preventing thread death during fork operations.
2. **Deterministic Concurrency Semaphore:**
   - A global bounded semaphore (`_heavy_operation_semaphore = threading.BoundedSemaphore(1)`) serializes heavy image convolution and LSB embedding tasks to guarantee process memory never spikes past the 512 MB threshold.
3. **Stateless Cleanup:**
   - Temporary carrier uploads and generated artifacts are registered in an exception-safe removal list unlinked in `finally` blocks. Files are wiped immediately after streaming or after 5 minutes by the cleanup daemon.

---

## 4. Local Development

### Virtual Environment Setup
```bash
cd backend
python -m venv .venv

# Windows (Command Prompt / PowerShell):
.venv\Scripts\activate

# Linux / macOS:
source .venv/bin/activate

# Install dependencies:
pip install -r requirements.txt
```

### Running Development Server
```bash
python app.py
```
The server will bind to `http://127.0.0.1:5000`.

---

## 5. Running Tests

InvisioVault includes an automated test suite covering cryptographic integrity, edge-case decodes, and memory recovery:

```bash
# Run all integration tests
python -m pytest tests/test_integration.py -v

# Run concurrency and memory recovery benchmarks
python -m pytest tests/test_concurrency.py -v
python -m pytest tests/test_memory_recovery.py -v

# Test Reed-Solomon error correction under noise
python -m pytest tests/test_differential_ecc.py -v

# Test camera scan decoder and cache deduplication
python -m pytest tests/test_camera_scan.py -v
```
