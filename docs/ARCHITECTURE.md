# InvisioVault Technical Architecture & Cryptographic Specification

This document provides a comprehensive technical breakdown of the algorithms, binary wire formats, mathematical models, and operational architecture powering **InvisioVault**.

---

## 1. High-Level System Architecture

InvisioVault is engineered as a zero-retention, decoupled system consisting of a client-side interface and an ephemeral cryptographic backend.

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                 Client Layer (React 19 / Vite / Vercel)                 │
│  ├─ UI & Deep Route Manager (App.jsx, BrowserRouter)                    │
│  └─ WebRTC Camera Scanner & Dual-Canvas 2x Preprocessing                │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTPS / TLS 1.3
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Vercel Edge Distribution Layer                       │
│  └─ Edge Middleware (Bot Detection & Pre-rendered HTML Redirection)     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Proxy Routed Requests
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                Stateless Backend Service (Render 512 MB)                │
│  ├─ Gunicorn Master + Sync Worker + post_fork Cleanup Thread            │
│  ├─ Global Concurrency Semaphore (_heavy_operation_semaphore: 1)       │
│  └─ Flask REST API Router (14 Endpoints)                                │
└───────────────────┬───────────────────┬───────────────────┬─────────────┘
                    │                   │                   │
                    ▼                   ▼                   ▼
┌───────────────────────┐ ┌───────────────────────┐ ┌─────────────────────┐
│ Steganography Engine  │ │Universal Polyglot Eng.│ │  QR Stego Engine    │
│├─ Sobel Edge Texture  │ │├─ Dual-Parser Verify  │ │├─ Visual Masking    │
│├─ LSB Matching (±1)   │ │├─ ZIP CDFH/EOCD Parse │ │├─ Stream Fragment   │
│├─ Reed-Solomon ECC    │ │└─ Binary mmap Patch   │ │└─ zxing-cpp Decode  │
│└─ Feistel Permutation │ └───────────┬───────────┘ └──────────┬──────────┘
└───────────┬───────────┘             │                        │
            │                         │                        │
            └─────────────────────────┼────────────────────────┘
                                      ▼
                    ┌───────────────────────────────────┐
                    │       Crypto Core Subsystem       │
                    │  ├─ PBKDF2-HMAC-SHA256 (480k)     │
                    │  └─ Fernet (AES-128-CBC + HMAC)   │
                    └───────────────────────────────────┘
```

---

## 2. Steganography Engine: LSB Matching, Edge Guidance & Wire Formats

Traditional Least Significant Bit (LSB) steganography simply overwrites the lowest bit of pixel color channels with payload bits. This creates a statistical imbalance known as the **Asymmetric PoV (Pairs of Values) effect**, which can be easily detected by $\chi^2$ (Chi-square) steganalysis.

InvisioVault mitigates this via **Detection-Resistant LSB Matching (±1 adjustment)**, **Sobel Edge Texture Guidance**, and **Differential Reed-Solomon Error Correction**.

### 2.1 Wire Format Specifications

InvisioVault uses structured binary packaging embedded directly into the pixel bitstream.

#### Wire Format v4 (Current Production Writer: Fast Adaptive)
All v4 payloads begin with an unencrypted sequential header, followed by a pseudo-randomly permuted payload.

```
┌─────────────────┬───────────────────┬───────────────┬───────────────────────────┐
│ MAGIC (2 Bytes) │ Password Flag (1B)│ Salt (16 B)   │ Metadata Length (4B, BE)  │
│   0xFF 0x02     │   0x20 or 0x21    │ CSPRNG Bytes  │ uint32 Big-Endian         │
├─────────────────┴───────────────────┴───────────────┴───────────────────────────┤
│ Metadata (N Bytes): "filename|mime_type" (Encrypted if password enabled)        │
├─────────────────┬───────────────────┬───────────────────────────────────────────┤
│ Data Length (4B)│ Threshold (1 Byte)│ Payload Bitstream (Permuted via Feistel) │
│ uint32 BE       │ 0x00 - 0xFF       │ Compressed + ECC + Encrypted Data         │
└─────────────────┴───────────────────┴───────────────────────────────────────────┘
```

#### Supported Flag Bitmasks:
- `0x20` (`_FLAG_PLAIN_FAST`): Plain, compressed + Reed-Solomon ECC, fast adaptive embed with stored threshold (Current Writer).
- `0x21` (`_FLAG_ENC_ONLY_FAST`): Password protected (Fernet authenticated AES-128-CBC + HMAC), compressed + ECC, fast adaptive embed (Current Writer).
- `0x10`, `0x11`, `0x12`: Legacy v3 adaptive formats with stored threshold (fully supported for extraction).
- `0x00`, `0x01`, `0x03`, `0x04`, `0x05`, `0x06`: Legacy v1/v2 sequential and random formats (fully supported for extraction).

---

### 2.2 Sobel Edge Texture Guidance

Steganographic embedding is least perceptible to the human eye in high-frequency, complex textures (edges, foliage, hair, grain) and most noticeable in smooth, flat gradients (sky, skin).

InvisioVault applies a **$3 \times 3$ Sobel filter convolution** across the carrier image's luminance channel:

$$G_x = \begin{bmatrix} -1 & 0 & +1 \\ -2 & 0 & +2 \\ -1 & 0 & +1 \end{bmatrix} * I, \quad G_y = \begin{bmatrix} +1 & +2 & +1 \\ 0 & 0 & 0 \\ -1 & -2 & -1 \end{bmatrix} * I$$

$$G = \sqrt{G_x^2 + G_y^2}$$

1. An edge gradient magnitude map $G(x, y)$ is computed.
2. A binary search determines the optimal gradient threshold $T$ such that the number of eligible edge pixels ($G(x, y) \ge T$) exactly accommodates the payload plus error correction overhead.
3. The selected threshold $T$ is stored as a single byte in the header, allowing the extractor to reconstruct the identical pixel eligibility map without re-running optimization.

---

### 2.3 LSB Matching (±1 Randomization)

Instead of setting the target bit directly ($b_{target} = bit$), LSB matching inspects the current pixel byte $P$:

$$\text{If } (P \pmod 2) \ne bit: \quad P' = \begin{cases} P + 1 & \text{with probability } 0.5 \\ P - 1 & \text{with probability } 0.5 \end{cases}$$

Boundary cases ($P = 0$ and $P = 255$) are clamped. This random drift eliminates the artificial flattening of histogram pairs of values, blinding classic statistical detectors.

---

### 2.4 Pixel Dispersion via CSPRNG Feistel Permutation

To prevent localized clusters of modified pixels (which form visible artifacts), pixel locations are scattered across all eligible edge coordinates using a pseudo-random permutation generated by a **Feistel network** keyed by the 16-byte cryptographic salt.

---

### 2.5 ⚠️ CRITICAL LIMITATION: Carrier Degradation & Lossy Compression

> [!WARNING]
> **LSB Steganography CANNOT survive lossy image compression!**
> 
> When an image is uploaded to platforms like **WhatsApp, Twitter/X, Instagram, Facebook, Discord, or Telegram (in default photo mode)**, the platform's media pipeline aggressively converts the image into a lossy JPEG or WebP format with high quantization tables.
>
> Lossy compression works by discarding high-frequency spatial components — the exact least significant bits where the hidden data resides. **A single lossy recompression will permanently destroy the steganographic payload.**
>
> **Best Practice:**
> 1. Always transmit carrier images as **uncompressed raw files** (e.g. "Send as File / Document" in messaging apps, ZIP archives, Google Drive, or email attachments).
> 2. Prefer lossless formats: **PNG** or **BMP**. While JPEG can serve as a carrier in InvisioVault, it must remain bit-for-bit unchanged post-embedding.

---

## 3. Universal Polyglot Engine: Dual-Parser Format Concatenation

A polyglot file simultaneously satisfies two distinct file format parsers without error.

```
┌─────────────────────────────────────────────────────────────┐
│                    Carrier Header & Data                    │
│    (PNG, JPEG, PDF, MP4, MP3 parsed from file offset 0)     │
├─────────────────────────────────────────────────────────────┤
│                    Appended ZIP Archive                     │
│    • Local File Headers (LFH)                               │
│    • Deflated File Data                                     │
│    • Central Directory File Headers (CDFH) [PATCHED]        │
│    • End of Central Directory Record (EOCD) [PATCHED]       │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 The Offset Problem
Standard archive utilities (WinRAR, 7-Zip, macOS Archive Utility, Linux `unzip`) do **not** read ZIP files from the beginning. Instead, they seek from the **end of the file** backwards to find the **End of Central Directory (EOCD)** signature (`0x06054b50` / `PK\x05\x06`).

The EOCD record contains:
- `offset_to_cd`: The byte offset from the start of the file where the Central Directory begins.
- Each Central Directory header contains `offset_to_lfh`: The byte offset from the start of the file where that file's Local File Header begins.

When a ZIP archive is appended to a carrier file of size $S_{carrier}$, all absolute offsets stored inside the ZIP structures become incorrect by exactly $+S_{carrier}$. Simple concatenation breaks standard unzippers.

---

### 3.2 In-Memory Binary Offset Patching (`_fix_zip_offsets()`)

InvisioVault uses zero-copy memory mapping (`mmap`) to parse and rewrite all offsets in place:

1. Locate the EOCD record within the last 65,557 bytes of the file.
2. Read the 32-bit Central Directory offset at byte offset $+16$ of the EOCD.
3. If the offset is `0xFFFFFFFF` (ZIP64 format):
   - Locate the ZIP64 EOCD locator (`PK\x06\x07`) and ZIP64 EOCD record (`PK\x06\x06`).
   - Patch the 64-bit Central Directory offset at $+48$.
4. Patch the 32-bit EOCD offset:
   $$\text{offset}_{CD}' = \text{offset}_{CD} + S_{carrier}$$
5. Iterate through every Central Directory File Header (`PK\x01\x02`):
   - Patch the 32-bit Local Header relative offset at $+42$:
     $$\text{offset}_{LFH}' = \text{offset}_{LFH} + S_{carrier}$$

The resulting file functions flawlessly:
- Opening it in an image viewer or media player reads from byte 0 and ignores trailing data.
- Opening it in an archive manager or renaming to `.zip` parses from the EOCD and extracts the hidden files cleanly.

---

## 4. QR Code Steganography Engine

InvisioVault provides two complementary QR steganographic modes tailored for different use cases.

### 4.1 Mode 1: Visual Module Mode (Structural Isolation)
Encodes clean public data in the QR matrix while embedding the encrypted secret into non-critical data modules.
- **Structural Module Preservation:** Standard QR decoders fail if functional patterns are modified. InvisioVault builds an explicit bitmask isolating:
  - Finder patterns ($7\times7$ corners) and separators
  - Timing patterns (alternating row/column lines)
  - Alignment patterns (version-dependent $5\times5$ squares)
  - Format info modules and version info blocks
  - Quiet zone padding (4-module border)
- Hidden bits are embedded only into non-structural data modules using Reed-Solomon redundancy parity blocks.

---

### 4.2 Legacy Mode: Stream Mode (URL Fragment Transport — Read/Extract Only)
In earlier versions, secret data could be compressed, encrypted, and embedded into the URI Fragment (`#IVDATA:`):

```
https://public-domain.com/landing#IVDATA:eyJhbGciOiJGRVJORVQiLCJzYWx0Ijoi...
```

**Generation Status in v2.0+:**
- **Generation Retired:** Stream QR generation has been retired in production to eliminate URL fragment exposure in modern link-preview apps and ensure generated QR codes are 100% indistinguishable from standard barcodes. InvisioVault now generates QR codes exclusively using clean **Visual Module Steganography** (Mode 1).
- **Extraction Preserved:** Full Stream Mode decoding and `#IVDATA:` parsing remains active in `useQRScanner.js` and `/api/qr/scan` to preserve backwards compatibility when scanning legacy double-agent barcodes.

---

### 4.3 Real-Time WebRTC Camera Scanner Pipeline

The frontend camera scanner (`useQRScanner.js`) runs a continuous multi-stage pipeline:

```
Camera Video Stream (getUserMedia)
           │
           ▼
Canvas Frame Capture (Native Resolution)
           │
           ├──────────────────────────────────────────────┐
           ▼                                              ▼
   Original Canvas                                Enhanced Canvas
(Color preservation for                        (2x Bilinear Upscale +
  subtle visual modules)                        Grayscale + 50% Contrast)
           │                                              │
           ▼                                              ▼
     jsQR Detection                                 jsQR Detection
           │                                              │
           └──────────────────────┬───────────────────────┘
                                  │
                       QR Code Detected?
                       ├── Yes ──> Parse #IVDATA: locally or query /api/qr/scan
                       └── No  ──> Check SHA-256 Deduplication Cache
                                   └── Forward to Backend /api/qr/detect (zxing-cpp)
```

---

## 5. Memory Safety & Concurrency Control (Render 512 MB Architecture)

InvisioVault is deployed on Render's free tier with a strict **512 MB RAM limit**. High-resolution images (e.g. 24 MP phone photos) decompressed into raw uncompressed RGB arrays consume:

$$6000 \times 4000 \times 3 \text{ bytes} \approx 72 \text{ MB per buffer}$$

Multiple simultaneous uploads would trigger Linux OOM Killer terminations.

### Mitigations:
1. **Bounded Semaphore Concurrency:** All memory-intensive routes (`/api/hide`, `/api/extract`, `/api/polyglot/create`) acquire `_heavy_operation_semaphore = threading.BoundedSemaphore(1)` with a 30-second timeout.
2. **Immediate Temp Unlinking:** Every file write registers in an exception-safe `_remove_quietly()` cleanup list called inside `finally` blocks.
3. **Background Scavenger Thread:** `FileCleanupScheduler` runs independently in each Gunicorn worker (spawned via `post_fork` in `gunicorn.conf.py`) removing files older than 5 minutes.

---

## 6. Known Technical Limitations (v2.0.1)

To ensure cryptographic transparency, the following design boundaries are formally documented:

1. **Lossy Compression Incompatibility:**
   - LSB payloads are **permanently destroyed** by lossy image recompression (WhatsApp, Twitter/X, Instagram, Discord, and photo cloud sync tools). Carriers must be transmitted as uncompressed documents or raw binary files.
2. **QR Code Stream Generation Retired:**
   - Stream Mode (`#IVDATA:`) generation has been retired to eliminate URL fragment exposure in modern browsers and third-party barcode readers. QR code generation exclusively uses clean Visual Module Steganography. Extraction of legacy stream barcodes remains fully operational.
3. **macOS Finder Quick Look Anomaly:**
   - While polyglot PNG+ZIP files open perfectly in preview apps and unarchive cleanly in archive tools, macOS Quick Look may display an error on specific PNG+ZIP combinations if Apple's parser strictly rejects trailing bytes following the `IEND` chunk.
4. **Render Free-Tier Concurrency Serialization:**
   - Under Render's 512 MB memory ceiling, `_heavy_operation_semaphore` serializes heavy LSB image convolutions to 1 concurrent request per worker to eliminate Linux OOM terminations.

