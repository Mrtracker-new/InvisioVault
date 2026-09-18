# Security Policy & Threat Model

InvisioVault is committed to cryptographic rigor, software integrity, and responsible disclosure. As a privacy-focused utility designed to conceal and encrypt sensitive files, I treat security as a primary dimension of correctness.

---

## 1. Supported Versions

Security updates and patches are actively applied to the following versions:

| Version | Supported | Notes |
|---|---|---|
| `2.0.x` | :white_check_mark: Yes | Current production release (Fernet authenticated encryption, PBKDF2 at 480k iterations, universal polyglots, adaptive QR steganography). |
| `1.x` | :x: No | Legacy prototype. Extraction logic maintained for backwards compatibility only. |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability, side-channel leakage, or cryptographic defect within InvisioVault, please report it responsibly:

* **Primary Contact:** [rolanlobo901@gmail.com](mailto:rolanlobo901@gmail.com)
* **Lead Maintainer:** Rolan (RNR)
* **Response SLA:** I acknowledge receipt within **48 hours** and provide an initial technical triage assessment within **5 business days**.
* **Public Disclosure:** I kindly request that you refrain from public disclosure or filing public GitHub issues until a coordinated patch and security advisory have been released.

Please include the following in your report:
1. Vulnerability classification (e.g., cryptographic side-channel, algorithmic complexity attack, memory exhaustion, injection).
2. Proof-of-Concept (PoC) script, test vectors, or reproducible steps.
3. Affected components (`backend/utils/crypto_utils.py`, `steganography.py`, `polyglot.py`, `qr_stego.py`, or frontend handlers).
4. Potential impact assessment.

---

## 3. Formal Threat Model

To provide realistic security guarantees, InvisioVault explicitly defines its trust boundaries, protected assets, and operational limits.

### 3.1 Trust Boundaries & Architecture
InvisioVault operates on a client-server paradigm with an ephemeral, stateless backend:
- **Client (Frontend):** React 19 web application hosted on Vercel. Handles user interaction, camera frame ingestion for QR decoding, and client-side format checks.
- **API Server (Backend):** Flask / Gunicorn service hosted in a dedicated 512 MB memory envelope on Render. Processes cryptographic transformations, byte manipulation, and carrier reconstruction.

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Endpoint                        │
│   (Browser / Local Memory / WebRTC Camera Interface)        │
└───────────────┬─────────────────────────────▲───────────────┘
                │ TLS 1.3 (HTTPS)             │
                ▼                             │ Streamed Payload
┌─────────────────────────────────────────────┴───────────────┐
│              InvisioVault Stateless Backend                 │
│  - Rate Limiter (Memory / Token Bucket)                     │
│  - Input Sanitization & Magic-Byte File Validation          │
│  - Cryptographic Derivation (PBKDF2-HMAC-SHA256, 480k)     │
│  - Authenticated Encryption (Fernet: AES-128-CBC + HMAC)    │
│  - Steganographic Bitstream & Polyglot Offset Patching      │
│  - Ephemeral File Storage (Immediate Unlinking Post-Stream) │
└─────────────────────────────────────────────────────────────┘
```

---

### 3.2 In-Scope Protections (What InvisioVault Guarantees)

1. **Confidentiality & Authentication:**
   - Payloads encrypted with user passwords use **Fernet authenticated encryption** (AES-128-CBC with HMAC-SHA256 authentication). 
   - Encryption keys are derived using **PBKDF2-HMAC-SHA256** with **480,000 iterations** and a 16-byte cryptographically secure random salt (`os.urandom`), preventing precomputed dictionary or rainbow table attacks.
   - Any ciphertext tampering or invalid password results in an immediate authentication failure without leaking plaintext fragments.

2. **Zero Server Retention & Ephemeral Lifetime:**
   - The backend operates a strict zero-retention policy. Uploaded carriers and generated steganographic files are streamed to the user and scheduled for immediate unlinking (`os.remove`) in Python `finally` blocks.
   - An independent daemon thread (`FileCleanupScheduler`) continuously scrubs temporary files older than 5 minutes to protect against unhandled crash orphans.

3. **Input Sanitization & Resource Exhaustion Defense:**
   - **Decompression Bomb Guard:** Zip entries inflate with a hard ceiling of 50 MB (`_MAX_EXTRACT_SIZE`), preventing zip-bomb and memory-exhaustion exploits.
   - **Pixel Dimension Cap:** Images are capped at 25 Megapixels (`MAX_PIXEL_COUNT`) to prevent memory allocation denial-of-service.
   - **Path Traversal Shield:** Untrusted embedded filenames are sanitized via `secure_filename()` with strict fallbacks, preventing directory climbing attacks (e.g. `../../etc/passwd`).
   - **Deterministic Concurrency Semaphore:** Heavy operations (LSB encode/decode, polyglot concatenation) are constrained via bounded semaphores to prevent process memory thrashing.

4. **Visual & Structural Steganographic Invisibility:**
   - **LSB Matching (±1 Adjustment):** Rather than standard LSB replacement (which produces detectable parity asymmetry), InvisioVault uses ±1 random matching to defeat standard Chi-square ($\chi^2$) and Pairs of Values (PoV) statistical detectors.
   - **Edge Texture Guidance:** Sobel filter convolution identifies high-frequency texture edges where human visual perception is least sensitive to minor luminance variations.

---

### 3.3 Out-of-Scope Limitations (What InvisioVault Cannot Protect Against)

1. **Carrier Transcoding & Social Media Compression:**
   - Platforms such as **WhatsApp, Twitter/X, Instagram, Facebook, and Discord aggressively compress and transcode images to lossy JPEG or WebP formats.**
   - Lossy recompression discards least-significant bit information and destroys steganographic payloads.
   - **Mitigation:** Users must transmit steganographic carrier images as uncompressed documents/files (e.g., "Send as Document" in messaging apps, Google Drive, or email attachments).

2. **Compromised User Endpoints:**
   - If the user's device hosts malware, keyloggers, screen recorders, or hostile browser extensions, passwords and plaintexts can be captured before reaching the cryptographic layer.

3. **High-Density Machine Learning Steganalysis:**
   - While LSB matching and Sobel texture selection defeat classical statistical detectors, embedding at high capacity ratios (>50% of available carrier bytes) creates spatial correlation signatures detectable by specialized Convolutional Neural Networks (e.g., XuNet, SRNet).
   - **Mitigation:** For maximum covertness, maintain a payload-to-carrier size ratio below 10% and use high-entropy natural photographs as carrier images.

4. **Weak Passwords:**
   - While PBKDF2 at 480,000 iterations dramatically increases the cost of offline brute-forcing, short or dictionary passwords (e.g., `password123`) remain vulnerable. Users are strictly advised to use passphrases with 12+ characters.

---

## 4. Cryptographic Specifications At A Glance

| Primitive | Specification | Purpose |
|---|---|---|
| **Symmetric Cipher** | AES-128-CBC (PKCS7 padded) | Payload encryption |
| **Message Authentication** | HMAC-SHA256 | Ciphertext authenticity & integrity |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | Password-to-key stretching |
| **Iteration Count** | 480,000 iterations | Brute-force work factor |
| **Salt Size** | 16 bytes (128-bit CSPRNG) | Salt uniqueness per encryption |
| **Error Correction** | Reed-Solomon ($RS(255, 223)$) | Burst error recovery in image & QR |
| **Permutation** | CSPRNG-seeded Feistel cipher | Non-sequential pixel distribution |
