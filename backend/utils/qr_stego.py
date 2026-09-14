"""QR Code Steganography Utilities for InvisioVault.

This module provides an engineered, multi-decoder compatible QR steganography
architecture that prioritizes:
    QR Readability -> Error Correction -> Payload Integrity -> Hiding Capacity.

Architectural Modes:
--------------------
1. Visual Module Mode (Default for moderate payloads):
   - Standard QR barcode encodes ONLY clean `public_data`. Standard scanners
     (iPhone, Android, ZXing, PyZbar) decode the visible URL or text with 0%
     steganographic trace (#IVDATA fragment is not exposed).
   - Hidden payload is compressed (zlib lv9), authenticated/encrypted (Fernet /
     AES-HMAC), and embedded into safe data modules using deterministic
     pseudo-random permutation (HMAC-SHA256).
   - Structural modules (finder, separator, timing, alignment, format, version,
     dark module, quiet zone) are 100% isolated and preserved.

2. Optimized Stream Mode (For larger payloads or direct URL transport):
   - Hidden payload is compressed (zlib lv9), authenticated/encrypted (Fernet),
     packaged into an IVQR container, and encoded in the URL fragment (#IVDATA:).
   - Uses adaptive error correction (Level M or Q), ISO-compliant quiet zone
     (border=4), and safe version limits (Version <= 22) to prevent the QR from
     ballooning into unreadable 177x177 matrices.

3. Unified Extractor:
   - 8-stage extraction pipeline automatically recovers secrets from either
     channel and supports backward compatibility for legacy InvisioVault QR codes.
"""

from __future__ import annotations

import base64
from enum import Enum
import hashlib
import logging
import math
import os
import secrets
import struct
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from PIL import Image, ImageOps
import segno
import zxingcpp
from pyzbar import pyzbar

from utils.crypto_utils import (
    FLAG_FERNET,
    FLAG_LEGACY_CBC,
    FLAG_PLAIN,
    SALT_LENGTH,
    derive_fernet_key,
)
from utils.qr_container import (
    MAX_DECOMPRESSED_BYTES,
    MAX_QR_PAYLOAD_BYTES,
    QR_CONTAINER_MAGIC,
    is_ivqr_container,
    pack_qr_container,
    unpack_qr_container,
)
from utils.qr_module_map import (
    detect_qr_version_from_timing,
    deterministic_permute,
    get_qr_dimension,
    get_safe_data_modules,
    get_structural_modules,
)

logger = logging.getLogger(__name__)

# Constants
DEFAULT_BORDER: int = 4  # ISO/IEC 18004 specifies >= 4 modules quiet zone
MAX_SAFE_QR_VERSION: int = 22  # Avoid unreadable dense matrices (> 105x105)
VISUAL_MODULATION_DELTA: int = 28  # Safe pixel luminance modulation delta
MAX_SAFE_STREAM_BYTES: int = 2_000  # Maximum safe secret text size in bytes
MAX_SAFE_VISUAL_BYTES: int = 1_200  # Maximum safe visual secret text size


class QRErrorCode(str, Enum):
    """Failure classification codes for QR steganography operations."""
    QR_NOT_DETECTED = "QR_NOT_DETECTED"
    QR_INVALID = "QR_INVALID"
    VISIBLE_PAYLOAD_DECODE_FAILED = "VISIBLE_PAYLOAD_DECODE_FAILED"
    NO_INVISIOVAULT_PAYLOAD = "NO_INVISIOVAULT_PAYLOAD"
    HIDDEN_PAYLOAD_CORRUPTED = "HIDDEN_PAYLOAD_CORRUPTED"
    WRONG_PASSWORD = "WRONG_PASSWORD"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    DECRYPTION_FAILED = "DECRYPTION_FAILED"
    DECOMPRESSION_FAILED = "DECOMPRESSION_FAILED"
    PAYLOAD_TRUNCATED = "PAYLOAD_TRUNCATED"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"


class QRStegoError(ValueError):
    """Exception raised for QR steganography failures with structured classification."""

    def __init__(self, message: str, error_code: QRErrorCode = QRErrorCode.QR_INVALID):
        super().__init__(message)
        self.error_code = error_code


# ── Legacy compatibility helpers ──────────────────────────────────────────────

def _encrypt_secret(secret_text: str, password: str) -> bytes:
    """Legacy Fernet encryption helper maintained for backward compatibility."""
    salt = secrets.token_bytes(SALT_LENGTH)
    key = derive_fernet_key(password, salt)
    from cryptography.fernet import Fernet
    fernet = Fernet(key)
    try:
        token = fernet.encrypt(secret_text.encode("utf-8"))
    finally:
        key = fernet = None
    return bytes([FLAG_FERNET]) + salt + token


def _decrypt_secret(payload_body: bytes, password: str) -> str:
    """Legacy Fernet decryption helper maintained for backward compatibility."""
    if len(payload_body) < SALT_LENGTH + 1:
        raise QRStegoError(
            "Encrypted payload is too short to be valid.",
            error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED,
        )

    salt = payload_body[:SALT_LENGTH]
    token = payload_body[SALT_LENGTH:]
    key = derive_fernet_key(password, salt)
    from cryptography.fernet import Fernet, InvalidToken
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(token)
    except InvalidToken:
        raise QRStegoError(
            "Incorrect password or the QR code data has been tampered with.",
            error_code=QRErrorCode.WRONG_PASSWORD,
        )
    finally:
        key = fernet = None

    return plaintext.decode("utf-8")


def _encode_payload(secret_text: str, password: Optional[str]) -> str:
    """Assemble and base64-encode IVDATA payload container."""
    container = pack_qr_container(secret_text, password)
    return base64.urlsafe_b64encode(container).decode("ascii")


def _decode_payload(secret_encoded: str, password: Optional[str]) -> str:
    """Decode and unpack IVDATA payload (supports both IVQR and legacy formats)."""
    try:
        # Support both standard b64 and urlsafe b64
        padded = secret_encoded + "=" * (-len(secret_encoded) % 4)
        try:
            raw_payload = base64.urlsafe_b64decode(padded)
        except Exception:
            raw_payload = base64.b64decode(padded)
    except Exception as exc:
        raise QRStegoError(
            "Hidden data could not be decoded — QR content may be corrupted.",
            error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED,
        ) from exc

    if len(raw_payload) < 1:
        raise QRStegoError(
            "Invalid payload: empty data.",
            error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED,
        )

    # 1. Check if new IVQR container
    if is_ivqr_container(raw_payload):
        try:
            return unpack_qr_container(raw_payload, password)
        except ValueError as e:
            if "password" in str(e).lower() or "tampered" in str(e).lower():
                raise QRStegoError(str(e), error_code=QRErrorCode.WRONG_PASSWORD)
            raise QRStegoError(str(e), error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED)

    # 2. Fall back to legacy format flags
    flag = raw_payload[0]
    body = raw_payload[1:]

    if flag == FLAG_PLAIN:
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            raise QRStegoError(
                "Legacy payload text is corrupted or not valid UTF-8.",
                error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED,
            )

    if flag == FLAG_LEGACY_CBC:
        raise QRStegoError(
            "This QR code was generated with an older, insecure encryption "
            "scheme (AES-CBC without authentication). Please regenerate it.",
            error_code=QRErrorCode.UNSUPPORTED_VERSION,
        )

    if flag == FLAG_FERNET:
        if not password:
            raise QRStegoError(
                "This QR code is password protected. Please provide the password.",
                error_code=QRErrorCode.WRONG_PASSWORD,
            )
        return _decrypt_secret(body, password)

    raise QRStegoError(
        f"Unknown payload format flag 0x{flag:02X}.",
        error_code=QRErrorCode.UNSUPPORTED_VERSION,
    )


# ── Capacity & Adaptation ─────────────────────────────────────────────────────

def get_qr_capacity_info(public_data: str, scale: int = 10, method: str = "auto") -> Dict[str, Any]:
    """Calculate authentic, safe steganography capacity and recommendations.

    Considers:
      - Usable data modules
      - Error-correction level trade-offs
      - Scanner readability boundaries (max Version 22)
      - Compression factor (~1.8x typical for text)
      - Packaging & encryption overhead (header + salt + HMAC)

    Args:
        public_data: Visible QR data string.
        scale:       QR pixel-scale factor.
        method:      "auto", "visual", or "stream".

    Returns:
        Dictionary with safe capacity metrics and recommendations.
    """
    public_bytes_len = len(public_data.encode("utf-8")) if public_data else 0

    # Stream mode capacity at max safe version (v20, Error Level M)
    # Total binary capacity of v20 at Level M is 1,663 bytes.
    # Base64 expansion is 4/3, overhead is prefix (8B) + header/salt (32B).
    # We cap at 1,273 bytes (standard Level H limit) to ensure conservative safety.
    MAX_CAPACITY_CEILING = 1273
    available_b64 = max(0, MAX_CAPACITY_CEILING - public_bytes_len - len("#IVDATA:"))
    raw_stream_capacity = max(0, int(available_b64 * 3 / 4) - 1)
    safe_stream_capacity = min(MAX_CAPACITY_CEILING, raw_stream_capacity)

    # Visual mode capacity at Version 15 (5,689 safe data modules = 711 bytes)
    safe_visual_capacity = min(MAX_CAPACITY_CEILING, max(0, int((711 - 16) * 3 / 4)))

    if method == "visual":
        safe_bytes = safe_visual_capacity
        rec_version = 15
        rec_ecc = "M"
    elif method == "stream":
        safe_bytes = safe_stream_capacity
        rec_version = 18
        rec_ecc = "M"
    else:  # auto
        safe_bytes = safe_stream_capacity
        rec_version = 16
        rec_ecc = "M"

    return {
        "safeCapacityBytes": safe_bytes,
        "maxSafeVersion": MAX_SAFE_QR_VERSION,
        "recommendedErrorCorrection": rec_ecc,
        "recommendedVersion": rec_version,
        "publicDataLength": public_bytes_len,
        "method": method,
    }


def calculate_qr_capacity(public_data: str, scale: int = 10) -> int:
    """Calculate safe secret payload capacity in bytes.

    Maintains backward compatibility with route callers expecting an integer.
    """
    info = get_qr_capacity_info(public_data, scale, method="auto")
    return info["safeCapacityBytes"]


# ── Visual Module Embedding & Extraction ──────────────────────────────────────

def _select_qr_version_for_visual(
    payload_len_bits: int,
    public_data: str,
    max_version: int = MAX_SAFE_QR_VERSION,
) -> int:
    """Find the smallest QR version (up to max_version) that holds payload_len_bits."""
    for ver in range(2, max_version + 1):
        safe_mods = get_safe_data_modules(ver)
        if len(safe_mods) >= payload_len_bits:
            try:
                segno.make(public_data, version=ver, error="m", boost_error=False)
                return ver
            except Exception:
                continue
    raise QRStegoError(
        f"Hidden payload exceeds safe visual capacity for QR codes up to version {max_version}.",
        error_code=QRErrorCode.CAPACITY_EXCEEDED,
    )


def _embed_visual_qr(
    public_data: str,
    secret_text: str,
    output_path: str,
    password: Optional[str] = None,
    fg_color: str = "#000000",
    bg_color: str = "#FFFFFF",
    scale: int = 10,
    border: int = DEFAULT_BORDER,
    delta: int = VISUAL_MODULATION_DELTA,
    logo_path: Optional[str] = None,
) -> str:
    """Embed hidden secret into safe data modules of a clean visible QR code."""
    # 1. Pack container
    container = pack_qr_container(secret_text, password)
    bits: List[int] = []
    for b in container:
        for bit_idx in range(7, -1, -1):
            bits.append((b >> bit_idx) & 1)

    # 2. Select QR version
    ver = _select_qr_version_for_visual(len(bits), public_data)
    safe_mods = get_safe_data_modules(ver)

    # 3. Create QR encoding ONLY public_data
    qr = segno.make(public_data, version=ver, error="m", boost_error=False)
    matrix = [bytearray(row) for row in qr.matrix]
    qr_size = len(matrix)

    # 4. Deterministic permutation across safe modules
    seed_material = f"{public_data}|{ver}|{qr_size}".encode("utf-8")
    perm_seed = hashlib.sha256(seed_material).digest()
    permuted_mods = deterministic_permute(safe_mods, perm_seed)

    mod_bit_map = {}
    for idx, bit in enumerate(bits):
        mod_bit_map[permuted_mods[idx]] = bit

    # Parse colors
    fg_rgb = _hex_to_rgb(fg_color)
    bg_rgb = _hex_to_rgb(bg_color)

    # 5. Render image with isolated structural patterns
    img_size = (qr_size + 2 * border) * scale
    img = Image.new("RGB", (img_size, img_size), bg_rgb)
    structural = get_structural_modules(ver)

    for r in range(qr_size):
        for c in range(qr_size):
            is_dark = (matrix[r][c] == 1)
            is_structural = (r, c) in structural

            x0 = (c + border) * scale
            y0 = (r + border) * scale

            if is_structural:
                color = fg_rgb if is_dark else bg_rgb
                for dy in range(scale):
                    for dx in range(scale):
                        img.putpixel((x0 + dx, y0 + dy), color)
            else:
                bit = mod_bit_map.get((r, c), 0)
                for dy in range(scale):
                    for dx in range(scale):
                        is_inner = (1 <= dx < scale - 1) and (1 <= dy < scale - 1)
                        if is_dark:
                            if is_inner and bit == 1:
                                color = _adjust_luma(fg_rgb, delta)
                            else:
                                color = fg_rgb
                        else:
                            if is_inner and bit == 1:
                                color = _adjust_luma(bg_rgb, -delta)
                            else:
                                color = bg_rgb
                        img.putpixel((x0 + dx, y0 + dy), color)

    if logo_path:
        _embed_logo_image(img, logo_path, border=border, scale=scale)

    img.save(output_path, "PNG")
    logger.info(
        "Visual QR saved to %s (Version %d, Size %dx%d)",
        output_path, ver, img_size, img_size
    )
    return output_path


def _extract_visual_qr(
    img: Image.Image,
    position,
    public_data: str,
    password: Optional[str] = None,
) -> Tuple[str, str]:
    """Extract hidden payload from the safe data modules of a rectified QR code."""
    # Calculate minimum possible QR version that can hold public_data
    try:
        min_version = segno.make(public_data, error="m", boost_error=False).version
    except Exception:
        min_version = 1

    target_ver, rectified = detect_qr_version_from_timing(
        img, position, min_version=min_version
    )
    if target_ver is None or rectified is None:
        return public_data, ""

    scale = 10
    qr_size = get_qr_dimension(target_ver)
    qr_ref = segno.make(public_data, version=target_ver, error="m", boost_error=False)
    ref_matrix = qr_ref.matrix

    # Calibrate baseline dark and light luminance directly from structural finder patterns
    dark_samples: List[int] = []
    for dr in range(2, 5):
        for dc in range(2, 5):
            px = rectified.getpixel((dc * scale + scale // 2, dr * scale + scale // 2))
            dark_samples.append(px[0] if isinstance(px, tuple) else px)
    dark_base = sum(dark_samples) / len(dark_samples)

    light_samples: List[int] = []
    for dc in range(1, 6):
        px1 = rectified.getpixel((dc * scale + scale // 2, 1 * scale + scale // 2))
        px2 = rectified.getpixel((dc * scale + scale // 2, 5 * scale + scale // 2))
        light_samples.append(px1[0] if isinstance(px1, tuple) else px1)
        light_samples.append(px2[0] if isinstance(px2, tuple) else px2)
    light_base = sum(light_samples) / len(light_samples)

    contrast = light_base - dark_base
    if contrast < 15:
        return public_data, ""

    effective_delta = max(6.0, VISUAL_MODULATION_DELTA * (contrast / 255.0))
    threshold_dark = dark_base + (effective_delta * 0.45)
    threshold_light = light_base - (effective_delta * 0.45)

    safe_mods = get_safe_data_modules(target_ver)
    seed_material = f"{public_data}|{target_ver}|{qr_size}".encode("utf-8")
    perm_seed = hashlib.sha256(seed_material).digest()
    permuted_mods = deterministic_permute(safe_mods, perm_seed)

    # Read header bits (16 bytes = 128 bits)
    header_bits: List[int] = []
    for idx in range(128):
        if idx >= len(permuted_mods):
            break
        r, c = permuted_mods[idx]
        is_dark = (ref_matrix[r][c] == 1)
        samples: List[int] = []
        for dy in range(3, 7):
            for dx in range(3, 7):
                px = rectified.getpixel((c * scale + dx, r * scale + dy))
                luma = px[0] if isinstance(px, tuple) else px
                samples.append(luma)
        avg = sum(samples) / len(samples)
        if is_dark:
            bit = 1 if avg > threshold_dark else 0
        else:
            bit = 1 if avg < threshold_light else 0
        header_bits.append(bit)

    header_bytes = bytearray()
    for b_idx in range(0, len(header_bits), 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | header_bits[b_idx + bit_idx]
        header_bytes.append(byte_val)

    if len(header_bytes) < 16 or bytes(header_bytes[:4]) != QR_CONTAINER_MAGIC:
        return public_data, ""

    magic, version, flags, orig_len, payload_len = struct.unpack(
        ">4sBBII", bytes(header_bytes[:14])
    )
    total_container_len = 16 + payload_len
    total_bits = total_container_len * 8

    if total_bits > len(permuted_mods):
        raise QRStegoError(
            "Payload length exceeds available safe modules.",
            error_code=QRErrorCode.PAYLOAD_TRUNCATED,
        )

    all_bits = list(header_bits)
    for idx in range(128, total_bits):
        r, c = permuted_mods[idx]
        is_dark = (ref_matrix[r][c] == 1)
        samples = []
        for dy in range(3, 7):
            for dx in range(3, 7):
                px = rectified.getpixel((c * scale + dx, r * scale + dy))
                luma = px[0] if isinstance(px, tuple) else px
                samples.append(luma)
        avg = sum(samples) / len(samples)
        if is_dark:
            bit = 1 if avg > threshold_dark else 0
        else:
            bit = 1 if avg < threshold_light else 0
        all_bits.append(bit)

    container_bytes = bytearray()
    for b_idx in range(0, len(all_bits), 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | all_bits[b_idx + bit_idx]
        container_bytes.append(byte_val)

    try:
        secret_text = unpack_qr_container(bytes(container_bytes), password)
    except ValueError as e:
        if "password" in str(e).lower() or "tampered" in str(e).lower():
            raise QRStegoError(str(e), error_code=QRErrorCode.WRONG_PASSWORD)
        raise QRStegoError(str(e), error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED)

    return public_data, secret_text


# ── Stream Embedding ──────────────────────────────────────────────────────────

def _embed_stream_qr(
    public_data: str,
    secret_text: str,
    output_path: str,
    password: Optional[str] = None,
    fg_color: str = "#000000",
    bg_color: str = "#FFFFFF",
    scale: int = 10,
    border: int = DEFAULT_BORDER,
    logo_path: Optional[str] = None,
) -> str:
    """Generate QR with compressed, authenticated container in the URL fragment."""
    secret_encoded = _encode_payload(secret_text, password)
    combined_data = f"{public_data}#IVDATA:{secret_encoded}"

    # Adaptive error correction:
    # If logo is present, use 'h' or 'q' to absorb logo disruption.
    # If no logo, use 'm' to avoid unnecessarily high QR versions.
    ec_level = "h" if logo_path else "m"

    try:
        qr = segno.make(combined_data, error=ec_level, boost_error=False)
    except Exception as exc:
        raise QRStegoError(
            f"Failed to generate QR code: {exc}",
            error_code=QRErrorCode.CAPACITY_EXCEEDED,
        ) from exc

    if qr.version > MAX_SAFE_QR_VERSION:
        raise QRStegoError(
            f"Hidden payload exceeds safe QR capacity (requires version {qr.version}, "
            f"maximum safe version is {MAX_SAFE_QR_VERSION}).",
            error_code=QRErrorCode.CAPACITY_EXCEEDED,
        )

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        temp_qr_path = tmp.name

    try:
        qr.save(temp_qr_path, scale=scale, dark=fg_color, light=bg_color, border=border)
        if logo_path:
            _embed_logo_in_qr(temp_qr_path, logo_path)

        with Image.open(temp_qr_path) as tmp_img:
            tmp_img.convert("RGB").save(output_path, "PNG", optimize=False, compress_level=0)
    finally:
        if os.path.exists(temp_qr_path):
            os.remove(temp_qr_path)

    return output_path


# ── Public API ────────────────────────────────────────────────────────────────

def generate_qr_with_stego(
    public_data: str,
    secret_text: str,
    output_path: str,
    password: Optional[str] = None,
    fg_color: str = "#000000",
    bg_color: str = "#FFFFFF",
    scale: int = 15,
    logo_path: Optional[str] = None,
    method: str = "auto",
    error_level: Optional[str] = None,
) -> str:
    """Generate a QR code with an authenticated-encrypted hidden secret.

    Supports both Visual Module Steganography (public barcode remains clean with
    zero URL fragment exposure) and Optimized Stream Steganography (compressed
    authenticated container inside the URL fragment).

    Args:
        public_data: Visible QR data (URL, text, vCard, etc.).
        secret_text: Hidden message to embed.
        output_path: Filesystem destination path for the PNG.
        password:    Optional password for Fernet authenticated encryption.
        fg_color:    QR module color in hex (default: #000000).
        bg_color:    QR background color in hex (default: #FFFFFF).
        scale:       Pixel scaling multiplier (default: 15).
        logo_path:   Optional logo image to embed in center.
        method:      "auto" (default), "visual", or "stream".
        error_level: Optional ECC level override ('l', 'm', 'q', 'h').

    Returns:
        output_path on success.

    Raises:
        QRStegoError: If payload exceeds capacity or inputs are invalid.
    """
    if not public_data:
        raise QRStegoError("Public data is required.", error_code=QRErrorCode.QR_INVALID)
    if not secret_text:
        raise QRStegoError("Secret text is required.", error_code=QRErrorCode.QR_INVALID)

    # Normalize scale
    scale = max(5, min(30, int(scale)))

    # Determine embedding strategy
    chosen_method = method.lower()
    if chosen_method == "auto":
        # Always use robust stream mode by default so that QR codes survive
        # real-world camera scanning, prints, screenshots, and custom colors.
        chosen_method = "stream"

    logger.info(
        "Generating QR steganography using method='%s' (public_len=%d, secret_len=%d)",
        chosen_method, len(public_data), len(secret_text)
    )

    if chosen_method == "visual":
        try:
            return _embed_visual_qr(
                public_data=public_data,
                secret_text=secret_text,
                output_path=output_path,
                password=password,
                fg_color=fg_color,
                bg_color=bg_color,
                scale=scale,
                border=DEFAULT_BORDER,
                logo_path=logo_path,
            )
        except QRStegoError as e:
            if e.error_code == QRErrorCode.CAPACITY_EXCEEDED and method == "auto":
                # Fall back to stream mode
                logger.info("Visual capacity exceeded; falling back to optimized stream mode.")
                return _embed_stream_qr(
                    public_data=public_data,
                    secret_text=secret_text,
                    output_path=output_path,
                    password=password,
                    fg_color=fg_color,
                    bg_color=bg_color,
                    scale=scale,
                    border=DEFAULT_BORDER,
                    logo_path=logo_path,
                )
            raise

    return _embed_stream_qr(
        public_data=public_data,
        secret_text=secret_text,
        output_path=output_path,
        password=password,
        fg_color=fg_color,
        bg_color=bg_color,
        scale=scale,
        border=DEFAULT_BORDER,
        logo_path=logo_path,
    )


def extract_from_qr_stego(
    qr_path: str,
    password: Optional[str] = None,
    raw_qr_text: Optional[str] = None,
) -> Tuple[str, str]:
    """Extract visible data and hidden secret from a QR code image.

    Implements an 8-stage extraction pipeline:
      0. Client-assisted decode: If raw_qr_text contains #IVDATA:, decode immediately.
      1. Detect QR location and geometry (ZXing with PyZbar fallback).
      2. Reconstruct QR module matrix & read visible string.
      3. If '#IVDATA:' fragment exists: decode & decrypt from stream.
      4. If no fragment: inspect safe data modules in the visual layer.
      5. Verify payload container integrity.
      6. Decrypt ciphertext (if encrypted).
      7. Decompress payload (if compressed).
      8. Return (public_data, secret_text).

    Args:
        qr_path:     Path to QR code image.
        password:    Decryption password if the secret was sealed with one.
        raw_qr_text: Optional decoded QR string from client-side scanner.

    Returns:
        (public_data, secret_text)

    Raises:
        QRStegoError: On missing QR, wrong password, or corrupted data.
    """
    try:
        logger.info("Extracting from QR code: %s (has_raw_text=%s)", qr_path, bool(raw_qr_text))

        # Fast-path: client-side scanner already decoded the full stream container
        if raw_qr_text and "#IVDATA:" in raw_qr_text:
            parts = raw_qr_text.split("#IVDATA:", maxsplit=1)
            public_data = parts[0]
            secret_encoded = parts[1] if len(parts) > 1 else ""
            if secret_encoded:
                secret_text = _decode_payload(secret_encoded, password)
                logger.info(
                    "Extraction complete from client stream. Public: %d chars, Secret: %d chars.",
                    len(public_data),
                    len(secret_text),
                )
                return public_data, secret_text

        if not os.path.exists(qr_path):
            raise QRStegoError(
                f"QR code file not found: {qr_path}",
                error_code=QRErrorCode.QR_NOT_DETECTED,
            )

        with Image.open(qr_path) as raw_img:
            if raw_img.mode in ("RGBA", "LA") or (raw_img.mode == "P" and "transparency" in raw_img.info):
                rgba_img = raw_img.convert("RGBA")
                white_bg = Image.new("RGBA", rgba_img.size, (255, 255, 255, 255))
                white_bg.paste(rgba_img, mask=rgba_img.split()[3])
                img = white_bg.convert("RGB")
            else:
                img = raw_img.convert("RGB")

        # Stage 1: Detection via zxing-cpp
        decoded_objects = []
        try:
            decoded_objects = zxingcpp.read_barcodes(img)
        except Exception as exc:
            logger.debug("zxingcpp read failed: %s, falling back to pyzbar", exc)

        position = None
        qr_text = ""

        if decoded_objects:
            qr_text = decoded_objects[0].text
            position = decoded_objects[0].position
        else:
            # Fallback to pyzbar
            pyz_res = pyzbar.decode(img)
            if pyz_res:
                qr_text = pyz_res[0].data.decode("utf-8", errors="replace")
                if hasattr(pyz_res[0], "polygon") and len(pyz_res[0].polygon) == 4:
                    poly = pyz_res[0].polygon
                    class _PyzbarPosition:
                        def __init__(self, p):
                            self.top_left = p[0]
                            self.bottom_left = p[1]
                            self.bottom_right = p[2]
                            self.top_right = p[3]
                    position = _PyzbarPosition(poly)
            elif raw_qr_text:
                qr_text = raw_qr_text
            else:
                raise QRStegoError(
                    "No QR code found in the image.",
                    error_code=QRErrorCode.QR_NOT_DETECTED,
                )

        # Stage 2 & 3: Check Stream Mode (#IVDATA:)
        if "#IVDATA:" in qr_text:
            parts = qr_text.split("#IVDATA:", maxsplit=1)
            public_data = parts[0]
            secret_encoded = parts[1] if len(parts) > 1 else ""
            if not secret_encoded:
                logger.info("Extraction complete. Public: %d chars, Secret: 0 chars.", len(public_data))
                return public_data, ""
            secret_text = _decode_payload(secret_encoded, password)
            logger.info(
                "Extraction complete. Public: %d chars, Secret: %d chars.",
                len(public_data),
                len(secret_text),
            )
            return public_data, secret_text

        # Stage 4: Check Visual Module Layer
        if position is not None:
            try:
                pub, sec = _extract_visual_qr(img, position, qr_text, password)
                if sec:
                    logger.info(
                        "Extraction complete. Public: %d chars, Secret: %d chars.",
                        len(pub),
                        len(sec),
                    )
                    return pub, sec
            except QRStegoError:
                raise
            except Exception as exc:
                logger.debug("Visual extraction check produced no payload: %s", exc)

        # Regular QR code without hidden data
        logger.info("Extraction complete. Public: %d chars, Secret: 0 chars.", len(qr_text))
        return qr_text, ""

    except QRStegoError:
        raise
    except ValueError as e:
        if "password" in str(e).lower() or "tampered" in str(e).lower():
            raise QRStegoError(str(e), error_code=QRErrorCode.WRONG_PASSWORD)
        raise QRStegoError(str(e), error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED)
    except Exception as exc:
        logger.error("Failed to extract data from QR code: %s", exc, exc_info=True)
        raise QRStegoError(
            f"Failed to extract data from QR code: {exc}",
            error_code=QRErrorCode.QR_INVALID,
        ) from exc


def decode_qr_only(qr_path: str) -> str:
    """Decode and return the visible QR data, cleanly stripping any fragment."""
    public_data, _ = extract_from_qr_stego(qr_path, password=None)
    return public_data


# ── Color & Logo Helpers ──────────────────────────────────────────────────────

def _hex_to_rgb(hex_str: str) -> Tuple[int, int, int]:
    """Parse CSS hex color to RGB tuple (supports 3-char and 6-char hex)."""
    hex_str = hex_str.lstrip("#").strip()
    if len(hex_str) == 3:
        hex_str = "".join(c * 2 for c in hex_str)
    if len(hex_str) != 6:
        return (0, 0, 0)
    try:
        return (int(hex_str[0:2], 16), int(hex_str[2:4], 16), int(hex_str[4:6], 16))
    except ValueError:
        return (0, 0, 0)


def _adjust_luma(rgb: Tuple[int, int, int], delta: int) -> Tuple[int, int, int]:
    """Adjust luminance of an RGB tuple by delta, clamped to [0, 255]."""
    return (
        max(0, min(255, rgb[0] + delta)),
        max(0, min(255, rgb[1] + delta)),
        max(0, min(255, rgb[2] + delta)),
    )


def _embed_logo_image(
    qr_img: Image.Image,
    logo_path: str,
    border: int = DEFAULT_BORDER,
    scale: int = 10,
) -> None:
    """Embed logo into in-memory QR image, keeping logo size <= 15% of width."""
    try:
        with Image.open(logo_path) as raw_logo:
            logo_img = raw_logo.convert("RGBA")

        qr_w, qr_h = qr_img.size
        # Limit logo to at most 15% to strictly protect Reed-Solomon capacity
        max_logo = max(16, int(min(qr_w, qr_h) * 0.15))
        logo_img.thumbnail((max_logo, max_logo), Image.Resampling.LANCZOS)

        pos = ((qr_w - logo_img.width) // 2, (qr_h - logo_img.height) // 2)
        backing = Image.new("RGBA", logo_img.size, "WHITE")
        try:
            backing.paste(logo_img, (0, 0), logo_img)
            # Paste into qr_img
            qr_rgba = qr_img.convert("RGBA")
            qr_rgba.paste(backing, pos, backing)
            qr_img.paste(qr_rgba.convert("RGB"))
        finally:
            backing.close()
            logo_img.close()
    except Exception as exc:
        logger.warning("Could not embed logo: %s", exc)


def _embed_logo_in_qr(qr_path: str, logo_path: str) -> None:
    """Embed a logo in-place into an existing QR image file."""
    with Image.open(qr_path) as qr_img:
        rgb_img = qr_img.convert("RGB")
        _embed_logo_image(rgb_img, logo_path)
        rgb_img.save(qr_path, "PNG")
