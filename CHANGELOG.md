# Changelog

All notable changes to InvisioVault are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.1] - 2026-09-18

### Added
- **QR Code Steganography Suite:** Dual-mode QR generation and scanning using Visual Module Mode (structural isolation) and Stream Mode (URL fragment `#IVDATA:` scheme).
- **Live Camera QR Scanner:** Real-time WebRTC camera scanner with dual-canvas contrast enhancement, 5-tier progressive hardware fallback, and in-memory zxing-cpp decoding.
- **Deduplication Frame Cache:** In-memory SHA-256 frame cache reducing repeated frame extraction overhead during camera scans by 60–80%.
- **Render Memory Envelope Hardening:** Deterministic concurrency semaphore (`_heavy_operation_semaphore`) and Gunicorn `post_fork` cleanup scheduler hook to eliminate OOM spikes on Render free-tier (512 MB).
- **Formal Documentation Suite:** Added comprehensive `docs/ARCHITECTURE.md`, `docs/API.md`, `SECURITY.md` (with Threat Model), and `CONTRIBUTING.md`.

### Changed
- **Rate Limiting Refinement:** Upgraded to Flask-Limiter 3.5 with route-specific decorators registered directly on application Blueprint factory.
- **Sanitized Production Error Messaging:** Integrated centralized `sanitize_error()` to prevent internal path and exception leakage.

### Fixed
- Fixed central directory offset recalculation in polyglot ZIPs exceeding 4 GB using 64-bit EOCD record locator patching.
- Resolved camera permission policy conflicts on Vercel preview environments.

---

## [2.0.0] - 2026-01-15

### Added
- **Cryptographic Ground-Up Rebuild:** Completely restructured architecture from the early prototype.
- **Authenticated Encryption:** Upgraded to Fernet (AES-128-CBC + HMAC-SHA256) with 480,000-iteration PBKDF2-HMAC-SHA256 key stretching.
- **Universal Polyglot Engine:** Concatenation and in-memory offset patching for images (PNG, JPG, BMP), PDFs, audio (MP3), and video (MP4) dual-format files.
- **Detection-Resistant LSB Matching:** Replaced basic LSB substitution with ±1 randomized matching and Sobel edge detection texture guidance to resist statistical chi-square steganalysis.
- **Wire Formats v2 & v3:** Introduced magic byte header detection (`0xFF 0x02`), dynamic salt allocation, and differential Reed-Solomon Error Correction Code (RSCodec).

---

## [1.0.0] - 2024-05-10

### Initial Prototype
- Basic Least-Significant-Bit (LSB) image steganography implementation.
- Proof-of-concept file hiding in uncompressed BMP and PNG images.
