"""
Steganography utilities for hiding and extracting files in images.

Wire format — v1 (legacy, still supported for extraction)
---------------------------------------------------------
Without password:
    [password_flag(1)=0x00] [metadata_length(2, BE)] [metadata: "filename|mime"(N)]
    [data_length(4, BE)] [compressed_data(M)]

With password (compress-then-encrypt):
    [password_flag(1)=0x01] [salt(16)] [metadata_length(2, BE)] [enc_metadata(N)]
    [data_length(4, BE)] [enc_payload(M)]
    enc_payload = Fernet(key).encrypt( zlib.compress(plaintext) )

Wire format — v2 (introduced to fix M-06)
-----------------------------------------
A v2 blob always starts with the two-byte magic sequence 0xFF 0x02.

Without password (flag 0x00):
    [MAGIC(2)=0xFF 0x02] [password_flag(1)=0x00] [metadata_length(4, BE)]
    [metadata: "filename|mime"(N)] [data_length(4, BE)] [compressed_data(M)]

With password — flag 0x01 (compress-then-encrypt, OLD):
    [MAGIC(2)=0xFF 0x02] [password_flag(1)=0x01] [salt(16)] [metadata_length(4, BE)]
    [enc_metadata(N)] [data_length(4, BE)] [enc_payload(M)]

With password — flag 0x03 (encrypt-only):
    [MAGIC(2)=0xFF 0x02] [password_flag(1)=0x03] [salt(16)] [metadata_length(4, BE)]
    [enc_metadata(N)] [data_length(4, BE)] [enc_payload(M)]
    enc_payload = Fernet(key).encrypt( plaintext )   ← NO compression

Wire format — v3 (detection‑resistant, LSB‑matching, ECC, stored threshold)
---------------------------------------------------------------------------
Header (embedded sequentially):
    [MAGIC(2)=0xFF 0x02] [password_flag(1)] [salt(16)] [metadata_length(4, BE)]
    [metadata(N)] [data_length(4, BE)] [threshold(1)] [ … payload (randomised) … ]

New flags:
    0x10  plain, compressed + ECC, adaptive embed with stored threshold
    0x11  encrypt‑only, compressed + ECC, adaptive embed (current writer)
    0x12  compress‑then‑encrypt, compressed + ECC, adaptive embed (future)

Old v3 flags (0x04, 0x05, 0x06) are still extractable by recomputing the threshold.

Payload processing order for new flags:
    file → zlib compress → ECC encode → (encrypt if flag 0x11/0x12) → payload
Extraction reverses:
    payload → (decrypt) → ECC decode → zlib decompress → original file

The adaptive threshold is stored in the header (1 byte) so extraction does not
need to recompute the edge map — it simply reads the stored value and applies
the same eligibility criterion.

LSB matching (±1 random adjustment) reduces detectability.
Pixel selection uses a CSPRNG‑based Feistel permutation keyed by the salt.

Wire format — v4 (current writer: fast adaptive)
------------------------------------------------
Header layout is identical to v3 (embedded sequentially):
    [MAGIC(2)=0xFF 0x02] [password_flag(1)] [salt(16)] [metadata_length(4, BE)]
    [metadata(N)] [data_length(4, BE)] [threshold(1)] [ … payload (randomised) … ]

Flags:
    0x20  plain, compressed + ECC, fast adaptive
    0x21  encrypt‑only, compressed + ECC, fast adaptive (current writer)

Differences from v3 (flags 0x10/0x11/0x12):
  * Payload positions come from a NumPy RandomState (MT19937) permutation of
    the eligible channels, seeded from HMAC(salt).  The MT19937 stream is
    frozen forever by NumPy (NEP 19), so it is stable across platforms and
    versions.  The permutation carries no secrecy either way — the salt sits
    in the public header — so nothing is lost versus the per‑position
    HMAC‑Feistel walk it replaces, and embedding a 4 MP image drops from
    ~10 minutes of pure‑Python HMAC calls to well under a second.
  * Edge scores are computed on LSB‑zeroed pixel values and the payload is
    embedded by LSB *replacement*.  Embedding therefore cannot change any
    pixel's edge score, so extraction recomputes the exact same eligible set.
    (v3 scored the full pixel values and embedded with ±1 LSB matching, which
    could flip the eligibility of pixels near the threshold between embed and
    extract and silently corrupt the payload.)
  * v3 flags (0x10/0x11/0x12) and old random flags (0x04/0x05/0x06) remain
    extractable via the legacy HMAC‑Feistel path.
"""
from __future__ import annotations

from PIL import Image, PngImagePlugin
import zlib
import mimetypes
import os
import secrets
import math
import hashlib
import hmac
import struct
from cryptography.fernet import Fernet
import itertools
import gc
import numpy as np

from utils.crypto_utils import derive_fernet_key

# ── Optional ECC library (Reed‑Solomon) ──────────────────────────────────────
try:
    import importlib
    _reedsolo = importlib.import_module("reedsolo")
    RSCodec = _reedsolo.RSCodec
    _ECC_AVAILABLE = True

    # Precomputed GF(256) multiplication lookup table (64 KiB)
    _rs_32 = RSCodec(32)
    _GF_MUL_TABLE = np.zeros((256, 256), dtype=np.uint8)
    for _i in range(256):
        for _j in range(256):
            _GF_MUL_TABLE[_i, _j] = _reedsolo.gf_mul(_i, _j)

    # 32 generator polynomial coefficients (excluding monic leading 1)
    _GEN_POLY = np.array(_rs_32.gen[32][1:], dtype=np.uint8)
    # Generator lookup table for synthetic division: (256, 32) uint8 (8 KiB)
    _GEN_LUT = _GF_MUL_TABLE[:, _GEN_POLY]

    # Syndrome evaluation power multipliers: (32, 256) uint8 (8 KiB)
    _SYN_MUL = np.zeros((32, 256), dtype=np.uint8)
    for _i in range(32):
        _x = _reedsolo.gf_pow(2, _i)
        _SYN_MUL[_i] = _GF_MUL_TABLE[:, _x]
except (ImportError, AttributeError):
    RSCodec = None
    _rs_32 = None
    _GF_MUL_TABLE = None
    _GEN_LUT = None
    _SYN_MUL = None
    _ECC_AVAILABLE = False

# ── Wire-format constants ──────────────────────────────────────────────────────
_V2_MAGIC: bytes = b"\xff\x02"

# Password-flag byte values
_FLAG_PLAIN_SEQUENTIAL:          int = 0x00   # v1/v2 plain, sequential
_FLAG_ENC_COMPRESSED_SEQUENTIAL: int = 0x01   # v1/v2 old encrypt+compress, sequential
_FLAG_ENC_ONLY_SEQUENTIAL:       int = 0x03   # v2 encrypt-only, sequential
_FLAG_PLAIN_RANDOM:              int = 0x04   # v3 plain, randomised (legacy, no stored threshold)
_FLAG_ENC_ONLY_RANDOM:           int = 0x05   # v3 encrypted, randomised (legacy, no stored threshold)
_FLAG_ENC_COMPRESSED_RANDOM:     int = 0x06   # v3 encrypted+compress, randomised (legacy)

# v3 adaptive flags with stored threshold and ECC after compression (legacy read-only)
_FLAG_PLAIN_ADAPTIVE_NEW:        int = 0x10   # plain, compressed+ECC, adaptive
_FLAG_ENC_ONLY_ADAPTIVE_NEW:     int = 0x11   # encrypt-only, compressed+ECC, adaptive
_FLAG_ENC_COMPRESSED_ADAPTIVE_NEW: int = 0x12 # encrypt+compress, compressed+ECC, adaptive

# v4 fast-adaptive flags: NumPy MT19937 permutation + LSB-replacement on
# LSB-zeroed edge scores.  Header layout identical to v3.  These are the
# flags the current writer produces.
_FLAG_PLAIN_FAST:    int = 0x20   # plain, compressed+ECC, fast adaptive (current writer)
_FLAG_ENC_ONLY_FAST: int = 0x21   # encrypt-only, compressed+ECC, fast adaptive (current writer)

_V1_META_LEN_BYTES: int = 2
_V2_META_LEN_BYTES: int = 4
_DATA_LEN_BYTES:    int = 4
_THRESHOLD_BYTES:   int = 1   # new header field

# ── Safety caps ───────────────────────────────────────────────────────────────
_MAX_METADATA_PLAIN_LEN: int = 512
_MAX_METADATA_ENC_LEN:   int = 1_024
_MAX_PAYLOAD_BYTES:      int = 100 * 1_024 * 1_024
_MAX_DECOMPRESSED_BYTES: int = 100 * 1_024 * 1_024
_DECOMPRESS_CHUNK:       int = 65_536

assert _MAX_METADATA_PLAIN_LEN <= 0xFFFF_FFFF
assert _MAX_METADATA_ENC_LEN   <= 0xFFFF_FFFF
assert _MAX_PAYLOAD_BYTES      <= 0xFFFF_FFFF

_derive_key_from_password = derive_fernet_key

# ── Streaming LSB primitives (sequential, for legacy extraction) ──────────────

def _iter_lsb_bytes(img: Image.Image):
    """Yield each LSB byte extracted from the RGB channels sequentially."""
    px = img.load()
    width, height = img.width, img.height
    byte = 0
    bit_count = 0
    for y in range(height):
        for x in range(width):
            pixel = px[x, y]
            for ch in pixel[:3]:
                byte = (byte << 1) | (ch & 1)
                bit_count += 1
                if bit_count == 8:
                    yield byte
                    byte = 0
                    bit_count = 0


def _read_exactly(gen, n: int, context: str = "data") -> bytes:
    buf = bytes(itertools.islice(gen, n))
    if len(buf) < n:
        raise ValueError(
            f"Image is too small or does not contain valid hidden data "
            f"(tried to read {n} bytes of {context}, got {len(buf)})."
        )
    return buf


# ── Internal helpers ───────────────────────────────────────────────────────────

def _encode_metadata_length(n: int) -> bytes:
    if n > _MAX_METADATA_ENC_LEN:
        raise ValueError(
            f"Metadata field length ({n} B) exceeds the maximum allowed "
            f"{_MAX_METADATA_ENC_LEN} B."
        )
    return n.to_bytes(_V2_META_LEN_BYTES, "big")


def _safe_decompress(data: bytes, max_size: int = _MAX_DECOMPRESSED_BYTES) -> bytes:
    decompressor = zlib.decompressobj()
    chunks: list[bytes] = []
    total = 0
    while data:
        chunk = decompressor.decompress(data, _DECOMPRESS_CHUNK)
        total += len(chunk)
        if total > max_size:
            raise ValueError(f"Decompressed data exceeds maximum allowed size ({max_size // (1024*1024)} MB).")
        chunks.append(chunk)
        if decompressor.eof:
            break
        data = decompressor.unconsumed_tail
        if not data and not chunk:
            break
    tail = decompressor.flush()
    total += len(tail)
    if total > max_size:
        raise ValueError(f"Decompressed data exceeds maximum allowed size ({max_size // (1024*1024)} MB).")
    chunks.append(tail)
    return b"".join(chunks)


# ── ECC wrapper (Reed‑Solomon, applied after compression) ─────────────────────

def _ecc_encode(data: bytes) -> bytes:
    """Vectorized Reed-Solomon encoding with bit-for-bit equivalence to reedsolo."""
    if not _ECC_AVAILABLE or _rs_32 is None or len(data) == 0:
        return data
    ksize = 223
    n = len(data)
    m = n // ksize
    remainder = n % ksize

    parts = []
    if m > 0:
        full_data = np.frombuffer(data[:m * ksize], dtype=np.uint8).reshape(m, ksize)
        buf = np.zeros((m, ksize + 32), dtype=np.uint8)
        buf[:, :ksize] = full_data
        for j in range(ksize):
            coef = buf[:, j]
            buf[:, j + 1:j + 33] ^= _GEN_LUT[coef]
        buf[:, :ksize] = full_data
        parts.append(buf.tobytes())

    if remainder > 0:
        chunk = data[m * ksize:]
        k = remainder
        buf = np.zeros(k + 32, dtype=np.uint8)
        buf[:k] = np.frombuffer(chunk, dtype=np.uint8)
        for j in range(k):
            coef = buf[j]
            if coef != 0:
                buf[j + 1:j + 33] ^= _GEN_LUT[coef]
        buf[:k] = np.frombuffer(chunk, dtype=np.uint8)
        parts.append(buf.tobytes())

    return b"".join(parts)


def _ecc_decode(data: bytes) -> bytes:
    """Vectorized syndrome evaluation for fast clean decode, with reedsolo fallback."""
    if not _ECC_AVAILABLE or _rs_32 is None or len(data) == 0:
        return data
    n = len(data)
    if n <= 32:
        try:
            decoded, *_ = _rs_32.decode(data)
            return bytes(decoded)
        except Exception:
            raise ValueError("ECC decoding failed — too many errors or corrupted data.")

    chunksize = 255
    m = n // chunksize
    remainder = n % chunksize

    # Evaluate syndromes in parallel across full chunks
    all_clean = True
    if m > 0:
        full_chunks = np.frombuffer(data[:m * chunksize], dtype=np.uint8).reshape(m, chunksize)
        for i in range(32):
            lut = _SYN_MUL[i]
            y = full_chunks[:, 0]
            for j in range(1, chunksize):
                y = lut[y] ^ full_chunks[:, j]
            if np.any(y != 0):
                all_clean = False
                break

    if all_clean and remainder > 0:
        rem_chunk = np.frombuffer(data[m * chunksize:], dtype=np.uint8)
        rem_len = len(rem_chunk)
        if rem_len <= 32:
            all_clean = False
        else:
            for i in range(32):
                lut = _SYN_MUL[i]
                y = rem_chunk[0]
                for j in range(1, rem_len):
                    y = lut[y] ^ rem_chunk[j]
                if y != 0:
                    all_clean = False
                    break

    if all_clean:
        # Fast path: 0 syndromes across all chunks; payload is uncorrupted
        parts = []
        if m > 0:
            full_chunks = np.frombuffer(data[:m * chunksize], dtype=np.uint8).reshape(m, chunksize)
            parts.append(full_chunks[:, :223].tobytes())
        if remainder > 0:
            parts.append(data[m * chunksize : n - 32])
        return b"".join(parts)

    # Fallback path: one or more blocks has non-zero syndromes; repair with reedsolo
    try:
        decoded, *_ = _rs_32.decode(data)
        return bytes(decoded)
    except Exception:
        raise ValueError("ECC decoding failed — too many errors or corrupted data.")


# ── Fast edge detection (Sobel on luminance) ──────────────────────────────────

def _luminance(r: int, g: int, b: int) -> int:
    """Return integer luminance 0‑255 from RGB channels."""
    return int(0.299 * r + 0.587 * g + 0.114 * b)


def _compute_edge_scores(px, width: int, height: int) -> bytearray:
    """Return per‑pixel Sobel edge magnitude (0‑255) using only luminance."""
    # Build luminance array (1 byte per pixel) — this is the only large allocation
    lum = bytearray(width * height)
    for y in range(height):
        row_start = y * width
        for x in range(width):
            r, g, b = px[x, y][:3]
            lum[row_start + x] = _luminance(r, g, b)

    scores = bytearray(width * height)
    for y in range(height):
        for x in range(width):
            # 3x3 neighbourhood with mirroring
            vals = []
            for dy in (-1, 0, 1):
                ny = max(0, min(y + dy, height - 1))
                for dx in (-1, 0, 1):
                    nx = max(0, min(x + dx, width - 1))
                    vals.append(lum[ny * width + nx])
            # Sobel kernels
            gx = (-1*vals[0] + 0*vals[1] + 1*vals[2]
                  -2*vals[3] + 0*vals[4] + 2*vals[5]
                  -1*vals[6] + 0*vals[7] + 1*vals[8])
            gy = (-1*vals[0] -2*vals[1] -1*vals[2]
                  +0*vals[3] + 0*vals[4] + 0*vals[5]
                  +1*vals[6] + 2*vals[7] + 1*vals[8])
            mag = math.sqrt(gx * gx + gy * gy)
            # scale to 0‑255 (most magnitudes < 1000 for 8‑bit images)
            scores[y * width + x] = min(255, int(mag * 0.25))
    return scores


def _find_threshold_from_histogram(hist: list[int], required_bits: int) -> int:
    """Find the highest threshold where cumulative eligible channels >= required_bits."""
    cumulative = 0
    for level in range(255, -1, -1):
        cumulative += hist[level]
        if cumulative >= required_bits:
            return level
    raise ValueError("Image texture capacity insufficient for payload.")


# ── CSPRNG‑based Feistel permutation (memoryless) ─────────────────────────────

def _feistel_permute(index: int, modulus_bits: int, key: bytes) -> int:
    """8‑round Feistel network on [0, 2^modulus_bits-1] keyed by *key*."""
    if modulus_bits <= 0:
        return 0
    modulus = 1 << modulus_bits
    half = modulus_bits // 2
    other = modulus_bits - half
    left = index >> other
    right = index & ((1 << other) - 1)

    for rnd in range(8):
        h = hmac.digest(key, struct.pack(">I", rnd) + right.to_bytes((other + 7) // 8, "big"), "sha256")
        f_int = int.from_bytes(h[: (half + 7) // 8], "big")
        if half > 0:
            f_int &= (1 << half) - 1
        new_left = right
        new_right = left ^ f_int
        left, right = new_left, new_right

    return (left << other) | right


def _permute_with_cycle_walk(index: int, max_val: int, key: bytes) -> int:
    """Permute index in [0, max_val-1] using Feistel and cycle‑walk."""
    if max_val <= 1:
        return 0
    bits = max_val.bit_length()
    val = _feistel_permute(index, bits, key)
    while val >= max_val:
        val = _feistel_permute(val, bits, key)
    return val


def _derive_perm_key(salt: bytes) -> bytes:
    """Key for Feistel permutation, independent of encryption key."""
    return hmac.digest(salt, b"lsb_embed_v3_perm", "sha256")


# ── v4 fast vectorised primitives ────────────────────────────────────────────

def _v4_seed_from_salt(salt: bytes) -> int:
    """Derive a 32-bit MT19937 seed from the public salt (HMAC, domain-separated)."""
    digest = hmac.digest(salt, b"lsb_embed_v4_perm", "sha256")
    return int.from_bytes(digest[:4], "big")


def _v4_edge_scores(rgb: np.ndarray, chunk_size: int = 512) -> np.ndarray:
    """Vectorised Sobel edge magnitude (0-255) over LSB-zeroed RGB.

    ``rgb`` is an (H, W, 3) uint8 array.  Luminance is computed on the
    LSB-cleared channels so the returned scores are invariant under LSB
    replacement — this is what lets extraction recompute the identical
    eligible set after embedding.  Output is a flat (H*W,) uint8 array in
    row-major (y, x) order, matching pixel index = y*W + x.

    Optimized for ultra-low peak memory: evaluates both luminance and Sobel
    in horizontal slices, avoiding large float64 image allocations.
    """
    H, W, _ = rgb.shape
    scores = np.empty((H, W), dtype=np.uint8)

    for start in range(0, H, chunk_size):
        end = min(start + chunk_size, H)
        r_start = max(0, start - 1)
        r_end = min(H, end + 1)
        sub_rgb = rgb[r_start:r_end]
        sub_lum = (
            0.299 * (sub_rgb[:, :, 0] & np.uint8(0xFE)) +
            0.587 * (sub_rgb[:, :, 1] & np.uint8(0xFE)) +
            0.114 * (sub_rgb[:, :, 2] & np.uint8(0xFE))
        )
        pad_top = 1 if start == 0 else 0
        pad_bottom = 1 if end == H else 0
        p_slice = np.pad(sub_lum, ((pad_top, pad_bottom), (1, 1)), mode="edge")

        gx = (
            -1 * p_slice[:-2, :-2] + 1 * p_slice[:-2, 2:]
            - 2 * p_slice[1:-1, :-2] + 2 * p_slice[1:-1, 2:]
            - 1 * p_slice[2:, :-2] + 1 * p_slice[2:, 2:]
        )
        gy = (
            -1 * p_slice[:-2, :-2] - 2 * p_slice[:-2, 1:-1] - 1 * p_slice[:-2, 2:]
            + 1 * p_slice[2:, :-2] + 2 * p_slice[2:, 1:-1] + 1 * p_slice[2:, 2:]
        )
        mag = np.sqrt(gx * gx + gy * gy) * 0.25
        scores[start:end] = np.minimum(255, mag.astype(np.int32)).astype(np.uint8)

    return scores.reshape(-1)


def _v4_eligible_channels(scores: np.ndarray, threshold: int,
                          header_bits: int, total_channels: int) -> np.ndarray:
    """Return sorted absolute channel indices eligible for payload embedding.

    A channel at absolute index ``abs_ch`` (= pixel_idx*3 + ch) is eligible
    when it lies past the sequential header region AND its pixel's edge score
    meets ``threshold``.  Order is ascending abs_ch, identical on embed and
    extract before the permutation is applied.

    Memory-optimized: uses np.flatnonzero with int32 on eligible pixels and
    expands to sorted channel offsets without 64-bit array overhead.
    """
    eligible_pixels = np.flatnonzero(scores >= threshold).astype(np.int32)
    if eligible_pixels.size == 0:
        return np.empty(0, dtype=np.int32)
    expanded = (eligible_pixels[:, None] * np.int32(3) + np.arange(3, dtype=np.int32)).reshape(-1)
    start_idx = np.searchsorted(expanded, header_bits)
    return expanded[start_idx:]


def _v4_threshold_from_scores(scores: np.ndarray, header_bits: int,
                              total_channels: int, required_bits: int) -> int:
    """Highest threshold whose eligible-channel count still covers required_bits.

    Uses a score-weighted histogram of per-pixel free-channel counts so the
    search is O(N + 256) rather than O(256*N).

    Memory-optimized: most pixels have exactly 3 free channels. Only pixels
    overlapping the header region differ, avoiding allocating multiple 64-bit arrays.
    """
    n_pixels = scores.shape[0]
    channels_at_level = np.bincount(scores, minlength=256).astype(np.int64) * 3
    first_full_pixel = min((header_bits + 2) // 3, n_pixels)
    for p in range(first_full_pixel):
        actual_free = max(0, min(3 * p + 3, total_channels) - max(3 * p, header_bits))
        diff = actual_free - 3
        channels_at_level[scores[p]] += diff

    cumulative = 0
    for level in range(255, -1, -1):
        cumulative += int(channels_at_level[level])
        if cumulative >= required_bits:
            return level
    raise ValueError("Image texture capacity insufficient for payload.")


# ── Legacy LSB matching (retained for backward compatibility / reference) ───────

def _lsb_match(pixel_channel: int, desired_bit: int) -> int:
    """Return channel value with LSB == desired_bit, using ±1 if needed.
    Unused in v4 fast-adaptive writer which uses LSB replacement.
    """
    if (pixel_channel & 1) == desired_bit:
        return pixel_channel
    if pixel_channel == 0:
        return 1
    if pixel_channel == 255:
        return 254
    return pixel_channel + secrets.choice((-1, 1))


# ── Public API ─────────────────────────────────────────────────────────────────

def hide_file_in_image(
    image_path: str,
    file_path: str,
    output_path: str,
    password: str = None,
    original_filename: str | None = None,
) -> str:
    """Hide a file using detection‑resistant steganography (new adaptive writer).

    - File is compressed, then Reed‑Solomon ECC is applied.
    - Only high‑texture pixels (Sobel edge magnitude) carry payload bits.
    - Edge scores are computed on LSB‑zeroed values and payload is embedded by
      LSB replacement, so scores (and thus eligibility) are identical on embed
      and extract.
    - Payload channel order is a NumPy MT19937 permutation seeded from the salt.
    - The adaptive threshold is stored in the header (1 byte).
    - An alpha channel, if present, is preserved untouched.
    - Original PNG metadata (text chunks, EXIF) is preserved.
    """
    # ── Open image, preserve metadata ─────────────────────────────────────────
    with Image.open(image_path) as original_img:
        original_info = original_img.info.copy() if original_img.format == "PNG" else {}
        # Payload is embedded only in the RGB channels; an alpha channel (if any)
        # is preserved untouched.  Work in RGB for embedding.
        has_alpha = original_img.mode in ("RGBA", "LA", "PA")
        alpha_arr = None
        if has_alpha:
            rgba = original_img.convert("RGBA")
            try:
                rgb_arr = np.asarray(rgba, dtype=np.uint8)[:, :, :3].copy()
                alpha_arr = np.asarray(rgba, dtype=np.uint8)[:, :, 3].copy()
                width, height = rgba.width, rgba.height
            finally:
                rgba.close()
        else:
            rgb_img = original_img.convert("RGB") if original_img.mode != "RGB" else original_img
            try:
                rgb_arr = np.array(rgb_img, dtype=np.uint8)
                width, height = rgb_img.width, rgb_img.height
            finally:
                if rgb_img is not original_img:
                    rgb_img.close()
    total_pixels = width * height
    if total_pixels > (_MAX_PAYLOAD_BYTES * 8 // 3):
        raise ValueError("Host image dimensions exceed the maximum supported size.")

    # ── 1. Prepare file data: compress → ECC → (encrypt) ──────────────────────
    with open(file_path, "rb") as f:
        file_data = f.read()

    compressed = zlib.compress(file_data, level=9)
    ecc_data = _ecc_encode(compressed)      # ECC after compression

    # Plain / encrypted path
    if password:
        payload_bytes_plain = ecc_data
        flag = _FLAG_ENC_ONLY_FAST
    else:
        payload_bytes_plain = ecc_data
        flag = _FLAG_PLAIN_FAST

    # ── 2. Metadata ──────────────────────────────────────────────────────────
    if not original_filename:
        original_filename = os.path.basename(file_path)
    ext = os.path.splitext(original_filename)[1].lower() or os.path.splitext(file_path)[1].lower()
    _MIME_MAP = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".bmp": "image/bmp", ".webp": "image/webp",
        ".pdf": "application/pdf", ".txt": "text/plain", ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".zip": "application/zip", ".apk": "application/vnd.android.package-archive",
        ".mp4": "video/mp4",
    }
    mime_type = _MIME_MAP.get(ext) or mimetypes.guess_type(original_filename)[0] or mimetypes.guess_type(file_path)[0] or "application/octet-stream"
    metadata_plain = f"{original_filename}|{mime_type}".encode("utf-8")
    if len(metadata_plain) > _MAX_METADATA_PLAIN_LEN:
        raise ValueError(f"Metadata too long ({len(metadata_plain)} B).")

    # ── 3. Encryption / pass‑through ──────────────────────────────────────────
    salt = secrets.token_bytes(16)
    if password:
        key = _derive_key_from_password(password, salt)
        fernet = Fernet(key)
        metadata_field = fernet.encrypt(metadata_plain)
        payload_field = fernet.encrypt(payload_bytes_plain)
        key = fernet = None
    else:
        metadata_field = metadata_plain
        payload_field = payload_bytes_plain

    # ── 4. Build header (without threshold yet) ───────────────────────────────
    metadata_length = _encode_metadata_length(len(metadata_field))
    data_length = len(payload_field).to_bytes(_DATA_LEN_BYTES, "big")
    header_base = (
        _V2_MAGIC +
        bytes([flag]) +
        salt +
        metadata_length +
        metadata_field +
        data_length
    )   # threshold will be appended after we determine it

    header_base_bits = len(header_base) * 8
    payload_bits = len(payload_field) * 8
    total_channels = width * height * 3
    if header_base_bits + payload_bits + _THRESHOLD_BYTES * 8 > total_channels:
        raise ValueError("Host image capacity insufficient for header, threshold, and payload.")

    # ── 5. Flatten channels; edge scores are LSB-invariant ────────────────────
    # flat[abs_ch] is the value of channel (abs_ch % 3) of pixel (abs_ch // 3),
    # with pixel index in row-major (y, x) order — matching _v4_edge_scores.
    flat = rgb_arr.reshape(-1)                        # (H*W*3,) uint8, view
    scores = _v4_edge_scores(rgb_arr)                 # (H*W,) uint8, LSB-invariant

    # ── 6. Find adaptive threshold over the region past the full header ───────
    full_header_len = len(header_base) + _THRESHOLD_BYTES
    header_total_bits = full_header_len * 8
    if header_total_bits + payload_bits > total_channels:
        raise ValueError("Host image capacity insufficient for header, threshold, and payload.")

    threshold = _v4_threshold_from_scores(
        scores, header_total_bits, total_channels, payload_bits
    )

    # ── 7. Embed the full header (header_base + threshold) sequentially ───────
    full_header = header_base + struct.pack("B", threshold)
    header_bits_arr = np.unpackbits(
        np.frombuffer(full_header, dtype=np.uint8)
    )                                                 # MSB-first, matches reader
    n_hdr = header_bits_arr.size
    flat[:n_hdr] = (flat[:n_hdr] & np.uint8(0xFE)) | header_bits_arr

    # ── 8. Embed payload into permuted eligible channels (LSB replacement) ────
    eligible = _v4_eligible_channels(scores, threshold, header_total_bits, total_channels)
    del scores
    gc.collect()

    if eligible.size < payload_bits:
        raise ValueError("Failed to embed all payload bits — image texture insufficient.")

    rng = np.random.RandomState(_v4_seed_from_salt(salt))
    perm_sample = rng.choice(eligible.size, size=payload_bits, replace=False)
    target_channels = eligible[perm_sample]
    del eligible, perm_sample

    payload_bits_arr = np.unpackbits(
        np.frombuffer(payload_field, dtype=np.uint8)
    )                                                 # MSB-first
    flat[target_channels] = (flat[target_channels] & np.uint8(0xFE)) | payload_bits_arr
    del target_channels, payload_bits_arr
    gc.collect()

    # ── 9. Reassemble and save with original PNG metadata ─────────────────────
    out_rgb = flat.reshape(height, width, 3)
    if has_alpha:
        out_arr = np.dstack([out_rgb, alpha_arr])
        host_img = Image.fromarray(out_arr, "RGBA")
    else:
        host_img = Image.fromarray(out_rgb, "RGB")

    pnginfo = PngImagePlugin.PngInfo()
    for k, v in original_info.items():
        if isinstance(v, str):
            pnginfo.add_text(k, v, zip=False)
    exif = original_info.get("exif")

    try:
        host_img.save(
            output_path, "PNG",
            optimize=False,
            compress_level=6,
            pnginfo=pnginfo,
            exif=exif,
        )
    finally:
        host_img.close()
    return output_path


def extract_file_from_image(
    image_path: str,
    password: str = None,
) -> tuple[bytes, str, str]:
    """Extract a hidden file (transparent v1/v2/v3/v4 support)."""
    # Normalize to RGB: the hide path always writes RGB/RGBA PNGs, but a
    # grayscale ("L"), palette ("P"), or CMYK upload would make px[x, y]
    # return an int (or 4-tuple), crashing pixel[:3] in _iter_lsb_bytes /
    # _compute_edge_scores with a 500.  RGBA→RGB drops alpha without
    # blending, so the embedded RGB channels are read back unchanged.
    raw_img = Image.open(image_path)
    img = None
    try:
        img = raw_img.convert("RGB") if raw_img.mode != "RGB" else raw_img
        if img is raw_img:
            img.load()
    finally:
        if raw_img is not None and img is not raw_img:
            raw_img.close()

    try:
        width, height = img.width, img.height
        total_channels = width * height * 3
        max_carriable = total_channels // 8

        gen_seq = _iter_lsb_bytes(img)
        first_two = _read_exactly(gen_seq, 2, "version header")

        if first_two == _V2_MAGIC:
            password_flag_byte = _read_exactly(gen_seq, 1, "password flag")[0]
            flag = password_flag_byte

            # Determine basic properties
            has_password = flag in (
                _FLAG_ENC_COMPRESSED_SEQUENTIAL, _FLAG_ENC_ONLY_SEQUENTIAL,
                _FLAG_ENC_ONLY_RANDOM, _FLAG_ENC_COMPRESSED_RANDOM,
                _FLAG_ENC_ONLY_ADAPTIVE_NEW, _FLAG_ENC_COMPRESSED_ADAPTIVE_NEW,
                _FLAG_ENC_ONLY_FAST,
            )
            is_fast = flag in (_FLAG_PLAIN_FAST, _FLAG_ENC_ONLY_FAST)   # v4
            is_v3_adaptive = flag in (
                _FLAG_PLAIN_ADAPTIVE_NEW, _FLAG_ENC_ONLY_ADAPTIVE_NEW,
                _FLAG_ENC_COMPRESSED_ADAPTIVE_NEW,
            )
            # Both v3 and v4 store the threshold byte in the header.
            is_new_adaptive = is_v3_adaptive or is_fast
            is_old_random = flag in (_FLAG_PLAIN_RANDOM, _FLAG_ENC_ONLY_RANDOM,
                                     _FLAG_ENC_COMPRESSED_RANDOM)
            is_random_embed = is_new_adaptive or is_old_random
            is_compressed = flag in (
                _FLAG_PLAIN_SEQUENTIAL, _FLAG_PLAIN_RANDOM,
                _FLAG_ENC_COMPRESSED_SEQUENTIAL, _FLAG_ENC_COMPRESSED_RANDOM,
                _FLAG_PLAIN_ADAPTIVE_NEW, _FLAG_ENC_COMPRESSED_ADAPTIVE_NEW,
            )

            if has_password and not password:
                raise ValueError("This file is password-protected. Please provide the password.")

            # Read salt (if needed).  Plain fast/adaptive flags still carry a
            # salt (used to seed the payload permutation), so include them.
            salt = b""
            if has_password or flag in (
                _FLAG_PLAIN_RANDOM, _FLAG_PLAIN_ADAPTIVE_NEW, _FLAG_PLAIN_FAST,
            ):
                salt = _read_exactly(gen_seq, 16, "salt")

            # Metadata length and field
            metadata_length = int.from_bytes(
                _read_exactly(gen_seq, _V2_META_LEN_BYTES, "metadata length"), "big"
            )
            max_meta_len = _MAX_METADATA_ENC_LEN if has_password else _MAX_METADATA_PLAIN_LEN
            if metadata_length == 0 or metadata_length > max_meta_len:
                raise ValueError("Metadata length is outside the valid range.")
            metadata_bytes = _read_exactly(gen_seq, metadata_length, "metadata")

            # Data length
            data_length = int.from_bytes(
                _read_exactly(gen_seq, _DATA_LEN_BYTES, "data length"), "big"
            )
            if data_length == 0 or data_length > min(max_carriable, _MAX_PAYLOAD_BYTES):
                raise ValueError("Data length is invalid or exceeds image capacity.")

            # For new adaptive format, read stored threshold
            threshold = None
            if is_new_adaptive:
                threshold = _read_exactly(gen_seq, _THRESHOLD_BYTES, "threshold")[0]
                header_bytes_consumed = (2 + 1 + len(salt) + _V2_META_LEN_BYTES +
                                         metadata_length + _DATA_LEN_BYTES + _THRESHOLD_BYTES)
            else:
                header_bytes_consumed = (2 + 1 + len(salt) + _V2_META_LEN_BYTES +
                                         metadata_length + _DATA_LEN_BYTES)
            header_bits = header_bytes_consumed * 8

            # Read payload
            if is_fast and data_length > 0:
                rgb_arr = np.asarray(img, dtype=np.uint8)
                flat = rgb_arr.reshape(-1)
                scores = _v4_edge_scores(rgb_arr)     # LSB-invariant, same as embed
                payload_bits = data_length * 8
                eligible = _v4_eligible_channels(scores, threshold, header_bits, total_channels)
                del scores
                gc.collect()

                if eligible.size < payload_bits:
                    raise ValueError("Adaptive extraction failed – not enough eligible channels.")
                rng = np.random.RandomState(_v4_seed_from_salt(salt))
                perm_sample = rng.choice(eligible.size, size=payload_bits, replace=False)
                target_channels = eligible[perm_sample]
                del eligible, perm_sample

                bits = (flat[target_channels] & 1).astype(np.uint8)
                del target_channels, flat, rgb_arr
                payload_field = np.packbits(bits).tobytes()
                del bits
                gc.collect()
            elif is_random_embed and data_length > 0:
                # ── v3 / legacy random path: pure-Python Feistel walk ─────────
                px = img.load()  # we need pixel access for edge scores and bit extraction
                scores = _compute_edge_scores(px, width, height)
                if not (is_new_adaptive and threshold is not None):
                    # Old random flags: recompute threshold from image
                    hist = [0] * 256
                    for pix_idx in range(width * height):
                        free_start = max(pix_idx * 3, header_bits)
                        free_end = min((pix_idx + 1) * 3, total_channels)
                        free_ch = max(0, free_end - free_start)
                        if free_ch > 0:
                            hist[scores[pix_idx]] += free_ch
                    threshold = _find_threshold_from_histogram(hist, data_length * 8)

                free_positions = total_channels - header_bits
                perm_key = _derive_perm_key(salt)
                payload_bytes = bytearray(data_length)
                bits_read = 0
                scan_idx = 0
                while bits_read < data_length * 8 and scan_idx < free_positions:
                    perm_pos = _permute_with_cycle_walk(scan_idx, free_positions, perm_key)
                    abs_ch = header_bits + perm_pos
                    pixel_idx = abs_ch // 3
                    ch_idx = abs_ch % 3
                    if scores[pixel_idx] >= threshold:
                        pix = px[pixel_idx % width, pixel_idx // width]
                        bit = pix[ch_idx] & 1
                        byte_idx = bits_read // 8
                        bit_pos = 7 - (bits_read % 8)
                        payload_bytes[byte_idx] |= bit << bit_pos
                        bits_read += 1
                    scan_idx += 1
                if bits_read < data_length * 8:
                    raise ValueError("Adaptive extraction failed – not enough eligible channels.")
                payload_field = bytes(payload_bytes)
            else:
                # Sequential payload (v1, v2, or plain sequential)
                payload_field = _read_exactly(gen_seq, data_length, "payload")

        else:
            # ── v1 parser ─────────────────────────────────────────────────────
            password_flag_byte = first_two[0]
            has_password = password_flag_byte == 0x01
            is_compressed = True
            is_new_adaptive = False
            if has_password and not password:
                raise ValueError("This file is password-protected.")
            salt = b""
            if has_password:
                remaining_salt = _read_exactly(gen_seq, 15, "encryption salt")
                salt = bytes([first_two[1]]) + remaining_salt
            if has_password:
                meta_len_bytes = _read_exactly(gen_seq, _V1_META_LEN_BYTES, "metadata length")
            else:
                second_byte = _read_exactly(gen_seq, 1, "metadata length")
                meta_len_bytes = bytes([first_two[1]]) + second_byte
            metadata_length = int.from_bytes(meta_len_bytes, "big")
            max_meta_len = _MAX_METADATA_ENC_LEN if has_password else _MAX_METADATA_PLAIN_LEN
            if metadata_length == 0 or metadata_length > max_meta_len:
                raise ValueError("Metadata length out of range.")
            metadata_bytes = _read_exactly(gen_seq, metadata_length, "metadata")
            data_length = int.from_bytes(
                _read_exactly(gen_seq, _DATA_LEN_BYTES, "data length"), "big"
            )
            if data_length == 0 or data_length > min(max_carriable, _MAX_PAYLOAD_BYTES):
                raise ValueError("Data length invalid.")
            payload_field = _read_exactly(gen_seq, data_length, "payload")

        # ── Decrypt if needed ─────────────────────────────────────────────────
        if has_password:
            try:
                key = _derive_key_from_password(password, salt)
                fernet = Fernet(key)
                metadata_plain = fernet.decrypt(metadata_bytes)
                payload_field = fernet.decrypt(payload_field)
            except Exception:
                raise ValueError("Incorrect password.")
            finally:
                key = fernet = None
        else:
            metadata_plain = metadata_bytes

        # ── Metadata parsing ──────────────────────────────────────────────────
        try:
            metadata = metadata_plain.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Metadata is not valid UTF-8. The image may be corrupted.")
        if "|" not in metadata:
            raise ValueError("Metadata malformed (missing separator).")
        original_filename, mime_type = metadata.rsplit("|", 1)

        # ── Reverse payload processing: (decrypt) → ECC decode → decompress ───
        # For new adaptive flags: payload is ECC(compressed(data)) [possibly encrypted]
        if is_new_adaptive:
            # ECC is always present, then compression
            plain_with_ecc = payload_field
            plain_compressed = _ecc_decode(plain_with_ecc)
            file_data = _safe_decompress(plain_compressed)
        else:
            # Legacy paths
            if is_compressed:
                file_data = _safe_decompress(payload_field)
            else:
                file_data = payload_field

        return file_data, original_filename, mime_type

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to extract file: {exc}") from exc
    finally:
        if img is not None:
            img.close()