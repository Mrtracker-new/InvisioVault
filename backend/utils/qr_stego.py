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

2. Legacy Stream Mode (Read/Extract-Only for backward compatibility):
   - In earlier versions, secret payloads were compressed (zlib lv9), authenticated/
     encrypted (Fernet), packaged into an IVQR container, and encoded in the URL
     fragment (#IVDATA:).
   - Generation has been retired in v2.0+ to eliminate URL fragment exposure in
     scanners and link-preview crawlers. Parsing logic is preserved exclusively in
     the extraction pipeline for backwards compatibility with legacy barcodes.

3. Unified Extractor:
   - 8-stage extraction pipeline automatically recovers secrets from either
     channel and supports backward compatibility for legacy InvisioVault QR codes.
"""

from __future__ import annotations

import base64
from enum import Enum
import hashlib
import io
import logging
import math
import os
import secrets
import struct
import tempfile
from typing import Any, Dict, List, Optional, Tuple, Sequence

import numpy as np
from PIL import Image, ImageOps, ImageDraw
from reedsolo import RSCodec, ReedSolomonError
import segno
import zxingcpp
try:
    from pyzbar import pyzbar
except (ImportError, OSError):
    pyzbar = None

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
    find_perspective_coeffs,
    get_qr_dimension,
    get_safe_data_modules,
    get_structural_modules,
    verify_finder_pattern,
)

logger = logging.getLogger(__name__)

# Constants
DEFAULT_BORDER: int = 4  # ISO/IEC 18004 specifies >= 4 modules quiet zone
MAX_SAFE_QR_VERSION: int = 22  # Avoid unreadable dense matrices (> 105x105)
VISUAL_MODULATION_DELTA: int = 45  # Boosted baseline luminance modulation delta
DARK_MODULATION_DELTA: int = 50    # High-SNR optical modulation for dark modules (immune to white blooming)
LIGHT_MODULATION_DELTA: int = 40   # Enhanced modulation delta for light modules
RS_HEADER_ECC_BYTES: int = 8       # Parity bytes for 16B container header (corrects up to 4 byte errors)
RS_BODY_ECC_BYTES: int = 24        # Parity bytes for payload body (corrects up to 12 byte errors)
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
    # Safe visual capacity at MAX_SAFE_QR_VERSION (v22)
    # Safe data modules for v22: 8,826 bits = 1,103 bytes.
    # Container overhead: 16B header + 16B salt + Fernet token overhead (~57B) + padding (~15B) = ~104B.
    safe_mods_count = len(get_safe_data_modules(MAX_SAFE_QR_VERSION))
    safe_visual_capacity = max(0, (safe_mods_count // 8) - 104)

    return {
        "safeCapacityBytes": safe_visual_capacity,
        "maxSafeVersion": MAX_SAFE_QR_VERSION,
        "recommendedErrorCorrection": "M",
        "recommendedVersion": 15,
        "publicDataLength": public_bytes_len,
        "method": "visual",
    }


def calculate_qr_capacity(public_data: str, scale: int = 10) -> int:
    """Calculate safe secret payload capacity in bytes.

    Maintains backward compatibility with route callers expecting an integer.
    """
    info = get_qr_capacity_info(public_data, scale, method="visual")
    return info["safeCapacityBytes"]


# ── Visual Module Embedding & Extraction ──────────────────────────────────────

def _count_white_neighbors(matrix: Sequence[Sequence[int]], r: int, c: int) -> int:
    """Count white (0) cardinal neighbors around module (r, c)."""
    size = len(matrix)
    wn = 0
    for dr, dc in ((-1, 0), (1, 0), (0, -1), (0, 1)):
        nr, nc = r + dr, c + dc
        if 0 <= nr < size and 0 <= nc < size:
            if matrix[nr][nc] == 0:
                wn += 1
        else:
            wn += 1  # Out-of-bounds border is white quiet zone
    return wn


def _order_dark_modules(
    dark_mods: Sequence[Tuple[int, int]],
    matrix: Sequence[Sequence[int]],
    seed_material: bytes,
) -> List[Tuple[int, int]]:
    """Order safe dark modules by ascending white neighbor count (lowest optical bleed first)."""
    seed = hashlib.sha256(seed_material + b"_ordered_dark").digest()

    def _key(mod: Tuple[int, int]):
        r, c = mod
        wn = _count_white_neighbors(matrix, r, c)
        h = hashlib.sha256(seed + f"{r},{c}".encode("utf-8")).digest()
        return (wn, h)

    return sorted(dark_mods, key=_key)


def _select_qr_version_for_visual(
    payload_len_bits: int,
    public_data: str,
    max_version: int = MAX_SAFE_QR_VERSION,
) -> int:
    """Find the smallest QR version (up to max_version) that holds payload_len_bits."""
    # Priority 1: Pick version where 100% of payload fits in safe dark modules (zero white blooming)
    for ver in range(2, max_version + 1):
        try:
            qr = segno.make(public_data, version=ver, error="m", boost_error=False)
            m = qr.matrix
            safe_mods = get_safe_data_modules(ver)
            dark_safe = [mod for mod in safe_mods if m[mod[0]][mod[1]] == 1]
            if len(dark_safe) >= payload_len_bits:
                return ver
        except Exception:
            continue

    # Priority 2: Fallback to all safe modules (both dark and light) if payload is very large
    for ver in range(2, max_version + 1):
        safe_mods = get_safe_data_modules(ver)
        if len(safe_mods) >= payload_len_bits:
            try:
                segno.make(public_data, version=ver, error="m", boost_error=False)
                return ver
            except Exception:
                continue

    raise QRStegoError(
        "This secret is too large to fit safely inside a visual steganographic QR code. "
        "Please shorten the secret message.",
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
    delta: int = DARK_MODULATION_DELTA,
    logo_path: Optional[str] = None,
) -> str:
    """Embed hidden secret into safe data modules of a clean visible QR code."""
    # 1. Pack container and apply 2-Stage Reed-Solomon Forward Error Correction
    container = pack_qr_container(secret_text, password)
    header = container[:16]
    body = container[16:]

    rsc_hdr = RSCodec(RS_HEADER_ECC_BYTES)
    rsc_body = RSCodec(RS_BODY_ECC_BYTES)
    hdr_fec = rsc_hdr.encode(header)
    body_fec = rsc_body.encode(body)
    fec_stream = bytes(hdr_fec) + bytes(body_fec)

    bits: List[int] = []
    for b in fec_stream:
        for bit_idx in range(7, -1, -1):
            bits.append((b >> bit_idx) & 1)

    # 2. Select QR version prioritizing safe dark modules (zero white blooming)
    ver = _select_qr_version_for_visual(len(bits), public_data)
    safe_mods = get_safe_data_modules(ver)

    # 3. Create QR encoding ONLY public_data
    qr = segno.make(public_data, version=ver, error="m", boost_error=False)
    matrix = [bytearray(row) for row in qr.matrix]
    qr_size = len(matrix)

    # 4. Safe modules & Low-Bleed Ordering (Dark-Priority with Neighbor Bleed Minimization)
    seed_material = f"{public_data}|{ver}|{qr_size}".encode("utf-8")
    dark_safe = [m for m in safe_mods if matrix[m[0]][m[1]] == 1]
    light_safe = [m for m in safe_mods if matrix[m[0]][m[1]] == 0]

    ordered_dark = _order_dark_modules(dark_safe, matrix, seed_material)
    seed_light = hashlib.sha256(seed_material + b"_light").digest()
    perm_light = deterministic_permute(light_safe, seed_light)
    permuted_mods = ordered_dark + perm_light

    mod_bit_map = {}
    for idx, bit in enumerate(bits):
        mod_bit_map[permuted_mods[idx]] = bit

    # Parse colors
    fg_rgb = _hex_to_rgb(fg_color)
    bg_rgb = _hex_to_rgb(bg_color)

    # 5. Render image with isolated structural patterns (vectorized module assignment)
    img_size = (qr_size + 2 * border) * scale
    structural = get_structural_modules(ver)
    dark_adj = _adjust_luma(fg_rgb, delta)
    light_adj = _adjust_luma(bg_rgb, -LIGHT_MODULATION_DELTA)

    arr = np.full((img_size, img_size, 3), bg_rgb, dtype=np.uint8)
    for r in range(qr_size):
        for c in range(qr_size):
            is_dark = (matrix[r][c] == 1)
            x0 = (c + border) * scale
            y0 = (r + border) * scale

            if (r, c) in structural:
                arr[y0:y0 + scale, x0:x0 + scale] = fg_rgb if is_dark else bg_rgb
            else:
                base_color = fg_rgb if is_dark else bg_rgb
                arr[y0:y0 + scale, x0:x0 + scale] = base_color
                if mod_bit_map.get((r, c), 0) == 1:
                    inner_color = dark_adj if is_dark else light_adj
                    arr[y0 + 1:y0 + scale - 1, x0 + 1:x0 + scale - 1] = inner_color

    img = Image.fromarray(arr, "RGB")

    try:
        if logo_path:
            _embed_logo_image(img, logo_path, border=border, scale=scale)
        img.save(output_path, "PNG")
    finally:
        img.close()
    logger.info(
        "Visual QR saved to %s (Version %d, Size %dx%d)",
        output_path, ver, img_size, img_size
    )
    return output_path


class QRPoint:
    """Simple 2D point representation for QR geometry."""

    def __init__(self, x: float, y: float):
        self.x = float(x)
        self.y = float(y)


class QRPosition:
    """Unified quadrilateral position container with optional pattern centroids."""

    def __init__(
        self,
        top_left: Any,
        bottom_left: Any,
        bottom_right: Any,
        top_right: Any,
        top_left_finder: Any = None,
        bottom_left_finder: Any = None,
        top_right_finder: Any = None,
        bottom_right_alignment: Any = None,
    ):
        self.top_left = top_left if hasattr(top_left, "x") else QRPoint(top_left[0], top_left[1])
        self.bottom_left = bottom_left if hasattr(bottom_left, "x") else QRPoint(bottom_left[0], bottom_left[1])
        self.bottom_right = bottom_right if hasattr(bottom_right, "x") else QRPoint(bottom_right[0], bottom_right[1])
        self.top_right = top_right if hasattr(top_right, "x") else QRPoint(top_right[0], top_right[1])
        self.top_left_finder = (
            top_left_finder if (top_left_finder is None or hasattr(top_left_finder, "x"))
            else QRPoint(top_left_finder[0], top_left_finder[1])
        )
        self.bottom_left_finder = (
            bottom_left_finder if (bottom_left_finder is None or hasattr(bottom_left_finder, "x"))
            else QRPoint(bottom_left_finder[0], bottom_left_finder[1])
        )
        self.top_right_finder = (
            top_right_finder if (top_right_finder is None or hasattr(top_right_finder, "x"))
            else QRPoint(top_right_finder[0], top_right_finder[1])
        )
        self.bottom_right_alignment = (
            bottom_right_alignment if (bottom_right_alignment is None or hasattr(bottom_right_alignment, "x"))
            else QRPoint(bottom_right_alignment[0], bottom_right_alignment[1])
        )


def _parse_client_corners(corners: Any) -> Optional[QRPosition]:
    """Normalize client-provided corner coordinates into a QRPosition object."""
    if not corners or not isinstance(corners, dict):
        return None
    try:
        def _parse_pt(p):
            if not p:
                return None
            if hasattr(p, "x") and hasattr(p, "y"):
                return QRPoint(float(p.x), float(p.y))
            if isinstance(p, dict) and "x" in p and "y" in p:
                return QRPoint(float(p["x"]), float(p["y"]))
            if isinstance(p, (list, tuple)) and len(p) >= 2:
                return QRPoint(float(p[0]), float(p[1]))
            return None

        # Format A: jsQR location object
        if "topLeftCorner" in corners and "topRightCorner" in corners:
            tl = _parse_pt(corners.get("topLeftCorner"))
            bl = _parse_pt(corners.get("bottomLeftCorner"))
            br = _parse_pt(corners.get("bottomRightCorner"))
            tr = _parse_pt(corners.get("topRightCorner"))
            tl_f = _parse_pt(corners.get("topLeftFinderPattern"))
            bl_f = _parse_pt(corners.get("bottomLeftFinderPattern"))
            tr_f = _parse_pt(corners.get("topRightFinderPattern"))
            br_a = _parse_pt(corners.get("bottomRightAlignmentPattern"))
            if tl and bl and br and tr:
                return QRPosition(tl, bl, br, tr, tl_f, bl_f, tr_f, br_a)

        # Format B: snake_case keys
        if "top_left" in corners and "top_right" in corners:
            tl = _parse_pt(corners.get("top_left"))
            bl = _parse_pt(corners.get("bottom_left"))
            br = _parse_pt(corners.get("bottom_right"))
            tr = _parse_pt(corners.get("top_right"))
            tl_f = _parse_pt(corners.get("top_left_finder"))
            bl_f = _parse_pt(corners.get("bottom_left_finder"))
            tr_f = _parse_pt(corners.get("top_right_finder"))
            br_a = _parse_pt(corners.get("bottom_right_alignment"))
            if tl and bl and br and tr:
                return QRPosition(tl, bl, br, tr, tl_f, bl_f, tr_f, br_a)
    except Exception as exc:
        logger.debug("Failed to parse client corners: %s", exc)
    return None
def _count_all_white_neighbors(matrix: Sequence[Sequence[int]], r: int, c: int) -> float:
    """Calculate effective white neighbor optical bleed (cardinal + diagonal)."""
    size = len(matrix)
    wn = 0.0
    for dr, dc in ((-1, 0), (1, 0), (0, -1), (0, 1)):
        nr, nc = r + dr, c + dc
        if 0 <= nr < size and 0 <= nc < size:
            if matrix[nr][nc] == 0:
                wn += 1.0
        else:
            wn += 1.0
    for dr, dc in ((-1, -1), (-1, 1), (1, -1), (1, 1)):
        nr, nc = r + dr, c + dc
        if 0 <= nr < size and 0 <= nc < size:
            if matrix[nr][nc] == 0:
                wn += 0.4
        else:
            wn += 0.4
    return wn


def _clahe_numpy(gray: np.ndarray, tile_grid: int = 8, clip_limit: float = 2.5) -> np.ndarray:
    """Pure-NumPy tile-based Contrast Limited Adaptive Histogram Equalization.

    Divides the grayscale image into `tile_grid x tile_grid` tiles, equalises
    each tile's histogram independently with contrast limit clipping and uniform
    excess redistribution, and bilinearly interpolates between tile centroids to
    prevent tile-boundary artifacts. Pure NumPy, zero external dependencies.
    """
    h, w = gray.shape
    th, tw = h / tile_grid, w / tile_grid
    luts = np.zeros((tile_grid, tile_grid, 256), dtype=np.uint8)
    for tr in range(tile_grid):
        for tc in range(tile_grid):
            y0, y1 = int(round(tr * th)), int(round((tr + 1) * th))
            x0, x1 = int(round(tc * tw)), int(round((tc + 1) * tw))
            tile = gray[y0:y1, x0:x1].ravel()
            hist, _ = np.histogram(tile, bins=256, range=(0, 256))
            clip_val = max(1, int(clip_limit * tile.size / 256.0))
            excess = np.sum(np.maximum(hist - clip_val, 0))
            hist = np.minimum(hist, clip_val) + (excess // 256)
            cdf = np.cumsum(hist)
            cdf_min = cdf[cdf > 0][0] if np.any(cdf > 0) else 0
            denom = max(1, cdf[-1] - cdf_min)
            luts[tr, tc] = np.round(((cdf - cdf_min) / denom) * 255).astype(np.uint8)

    cent_y = (np.arange(tile_grid) + 0.5) * th
    cent_x = (np.arange(tile_grid) + 0.5) * tw
    y_coords, x_coords = np.arange(h), np.arange(w)
    tr0 = np.clip(np.floor((y_coords - cent_y[0]) / th).astype(int), 0, tile_grid - 2)
    tc0 = np.clip(np.floor((x_coords - cent_x[0]) / tw).astype(int), 0, tile_grid - 2)
    tr1, tc1 = tr0 + 1, tc0 + 1
    wy = np.clip((y_coords - cent_y[tr0]) / th, 0.0, 1.0)[:, None]
    wx = np.clip((x_coords - cent_x[tc0]) / tw, 0.0, 1.0)[None, :]
    tr0_g, tr1_g = tr0[:, None], tr1[:, None]
    tc0_g, tc1_g = tc0[None, :], tc1[None, :]

    out_tl = luts[tr0_g, tc0_g, gray]
    out_tr = luts[tr0_g, tc1_g, gray]
    out_bl = luts[tr1_g, tc0_g, gray]
    out_br = luts[tr1_g, tc1_g, gray]
    top = (1.0 - wx) * out_tl + wx * out_tr
    bottom = (1.0 - wx) * out_bl + wx * out_br
    eq = (1.0 - wy) * top + wy * bottom
    return np.clip(eq, 0, 255).astype(np.uint8)


def _extract_visual_qr(
    img: Image.Image,
    position,
    public_data: str,
    password: Optional[str] = None,
    client_version: Optional[int] = None,
    debug_info: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Extract hidden payload from the safe data modules of a rectified QR code."""
    # Calculate minimum possible QR version that can hold public_data
    try:
        min_version = int(segno.make(public_data, error="m", boost_error=False).version)
    except Exception:
        min_version = 1

    scale = 10
    target_ver = None
    rectified = None

    target_ver, rectified = detect_qr_version_from_timing(
        img, position, min_version=min_version, target_version_hint=client_version
    )

    if target_ver is None or rectified is None:
        if debug_info is not None:
            debug_info["failureReason"] = "INVALID_VERSION"
        return public_data, ""

    qr_size = get_qr_dimension(target_ver)

    # ── Diagnostic Debug Dump (Enable via INVISIOVAULT_DEBUG_DUMP=true) ─────────
    ENABLE_DEBUG_SCAN_DUMP = os.getenv("INVISIOVAULT_DEBUG_DUMP", "false").strip().lower() == "true"
    debug_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "debug_scans")
    scan_timestamp: Optional[str] = None

    def _dump_debug_scan(img_or_arr: Any, suffix: str) -> None:
        if not ENABLE_DEBUG_SCAN_DUMP or not scan_timestamp:
            return
        try:
            os.makedirs(debug_dir, exist_ok=True)
            dump_filename = f"scan_{scan_timestamp}_{suffix}.png"
            dump_path = os.path.join(debug_dir, dump_filename)
            arr = np.array(img_or_arr)
            uint8_arr = np.clip(arr, 0, 255).astype(np.uint8)
            Image.fromarray(uint8_arr).save(dump_path, format="PNG")
            logger.info("[Diagnostic Dump] Saved %s to %s", suffix, dump_path)
            print(f"[Diagnostic Dump] Saved {suffix} to: {dump_path}")
        except Exception as dump_err:
            logger.warning("[Diagnostic Dump] Failed to save %s: %s", suffix, dump_err)

    if ENABLE_DEBUG_SCAN_DUMP:
        from datetime import datetime
        scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        _dump_debug_scan(rectified, "raw")

    qr_ref = segno.make(public_data, version=target_ver, error="m", boost_error=False)
    ref_matrix = qr_ref.matrix
    structural = get_structural_modules(target_ver)
    safe_mods = get_safe_data_modules(target_ver)
    seed_material = f"{public_data}|{target_ver}|{qr_size}".encode("utf-8")

    dark_safe = [m for m in safe_mods if ref_matrix[m[0]][m[1]] == 1]
    light_safe = [m for m in safe_mods if ref_matrix[m[0]][m[1]] == 0]

    # Permutations for candidate decoding
    # 1. Low-bleed ordered dark + light (2-Stage Reed-Solomon FEC format)
    ordered_dark = _order_dark_modules(dark_safe, ref_matrix, seed_material)
    seed_light = hashlib.sha256(seed_material + b"_light").digest()
    perm_light = deterministic_permute(light_safe, seed_light)
    permuted_mods_fec = ordered_dark + perm_light

    # 2. Dark-priority hash permuted (non-FEC dark-priority format)
    seed_dark = hashlib.sha256(seed_material + b"_dark").digest()
    perm_dark = deterministic_permute(dark_safe, seed_dark)
    permuted_mods_dark_priority = perm_dark + perm_light

    # 3. Legacy uniform permutation (original format)
    perm_seed_legacy = hashlib.sha256(seed_material).digest()
    permuted_mods_legacy = deterministic_permute(safe_mods, perm_seed_legacy)

    # ── PASS 1: Fast-Path Direct Extraction (<50ms) ─────────────────────────
    # Before running heavy Lanczos upscaling, CLAHE, and 5x5 median filtering,
    # attempt rapid bit extraction and Reed-Solomon header+body decoding directly
    # on the raw rectified image using fast 3x3 mean/center sampling.
    # Refinement: Explicitly compute raw_scale = rectified.size[0] // qr_size
    # so it does not accidentally use the upscaled scale variable intended for Pass 2.
    raw_rectified = rectified.copy()
    raw_scale = max(1, rectified.size[0] // qr_size)

    try:
        raw_gray = np.array(raw_rectified.convert("L"), dtype=np.uint8)
        raw_centers = (np.arange(qr_size) * raw_scale + (raw_scale // 2)).astype(int)

        if raw_scale >= 3:
            padded_raw = np.pad(raw_gray, pad_width=1, mode="edge")
            raw_windows = np.lib.stride_tricks.sliding_window_view(padded_raw, (3, 3))
            raw_module_samples = np.mean(
                raw_windows[raw_centers[:, None], raw_centers[None, :]], axis=(-2, -1)
            ).astype(np.float32)
        else:
            raw_module_samples = raw_gray[raw_centers[:, None], raw_centers[None, :]].astype(np.float32)

        raw_struct_dark = [float(raw_module_samples[r, c]) for r, c in structural if ref_matrix[r][c] == 1]
        raw_struct_light = [float(raw_module_samples[r, c]) for r, c in structural if ref_matrix[r][c] == 0]

        if raw_struct_dark and raw_struct_light:
            raw_dark_base = float(np.median(raw_struct_dark))
            raw_light_base = float(np.median(raw_struct_light))
            raw_contrast = raw_light_base - raw_dark_base

            if raw_contrast > 20.0:
                raw_eff_delta = DARK_MODULATION_DELTA * max(0.08, raw_contrast / 255.0)
                raw_bleed = min(2.5, max(0.0, (raw_contrast / 255.0) * 2.5))

                hdr_total_fec_bytes = 16 + RS_HEADER_ECC_BYTES
                if len(permuted_mods_fec) >= hdr_total_fec_bytes * 8:
                    rsc_hdr = RSCodec(RS_HEADER_ECC_BYTES)
                    dec_hdr = None
                    best_tf = None
                    fec_mods = permuted_mods_fec[:hdr_total_fec_bytes * 8]
                    f_rows = np.array([m[0] for m in fec_mods], dtype=np.intp)
                    f_cols = np.array([m[1] for m in fec_mods], dtype=np.intp)
                    f_is_dark = np.array([ref_matrix[r][c] == 1 for r, c in fec_mods], dtype=bool)
                    f_base = np.where(f_is_dark, raw_dark_base, raw_light_base)
                    f_eff_wn = np.array([_count_all_white_neighbors(ref_matrix, r, c) for r, c in fec_mods], dtype=np.float32)
                    f_avgs = raw_module_samples[f_rows, f_cols]

                    for tf in [0.50, 0.45, 0.55, 0.40, 0.60]:
                        t_delta = max(6.0, raw_eff_delta * tf)
                        t_dark = f_base + (f_eff_wn * raw_bleed) + t_delta
                        t_light = f_base - ((5.6 - f_eff_wn) * raw_bleed * 0.5) - t_delta
                        thresholds = np.where(f_is_dark, t_dark, t_light)
                        cur_bits = np.where(f_is_dark, f_avgs > thresholds, f_avgs < thresholds).astype(int).tolist()

                        raw_hdr_bytes = bytearray()
                        for b_idx in range(0, len(cur_bits) - 7, 8):
                            b_val = 0
                            for bit_idx in range(8):
                                b_val = (b_val << 1) | cur_bits[b_idx + bit_idx]
                            raw_hdr_bytes.append(b_val)

                        try:
                            dec_hdr_res, _, _ = rsc_hdr.decode(bytes(raw_hdr_bytes))
                            res_b = bytes(dec_hdr_res)
                            if len(res_b) >= 16 and res_b[:4] == QR_CONTAINER_MAGIC:
                                dec_hdr = res_b
                                best_tf = tf
                                break
                        except ReedSolomonError:
                            continue

                    if dec_hdr is not None:
                        magic, version, flags, orig_len, payload_len = struct.unpack(">4sBBII", dec_hdr[:14])
                        is_encrypted = bool(flags & 0x01)
                        if is_encrypted and not password:
                            if debug_info is not None:
                                debug_info["ivqrMagicDetected"] = True
                                debug_info["fastPath"] = True
                                debug_info["failureReason"] = "WRONG_PASSWORD"
                            raise QRStegoError(
                                "This QR code is password protected. Please provide the password.",
                                error_code=QRErrorCode.WRONG_PASSWORD,
                            )

                        rsc_body = RSCodec(RS_BODY_ECC_BYTES)
                        body_fec_len = len(rsc_body.encode(b"\x00" * payload_len))
                        total_fec_bits = (hdr_total_fec_bytes + body_fec_len) * 8

                        if total_fec_bits <= len(permuted_mods_fec):
                            body_mods = permuted_mods_fec[hdr_total_fec_bytes * 8 : total_fec_bits]
                            b_rows = np.array([m[0] for m in body_mods], dtype=np.intp)
                            b_cols = np.array([m[1] for m in body_mods], dtype=np.intp)
                            b_is_dark = np.array([ref_matrix[r][c] == 1 for r, c in body_mods], dtype=bool)
                            b_base = np.where(b_is_dark, raw_dark_base, raw_light_base)
                            b_eff_wn = np.array([_count_all_white_neighbors(ref_matrix, r, c) for r, c in body_mods], dtype=np.float32)
                            b_avgs = raw_module_samples[b_rows, b_cols]

                            dec_body = None
                            candidate_b_tfs: List[float] = [best_tf] if best_tf is not None else []
                            for tf_cand in [0.50, 0.55, 0.45, 0.60, 0.40, 0.35, 0.65]:
                                if tf_cand not in candidate_b_tfs:
                                    candidate_b_tfs.append(tf_cand)

                            for b_tf in candidate_b_tfs:
                                b_t_delta = max(6.0, raw_eff_delta * b_tf)
                                b_t_dark = b_base + (b_eff_wn * raw_bleed) + b_t_delta
                                b_t_light = b_base - ((5.6 - b_eff_wn) * raw_bleed * 0.5) - b_t_delta
                                b_thresholds = np.where(b_is_dark, b_t_dark, b_t_light)
                                cur_body_bits = np.where(b_is_dark, b_avgs > b_thresholds, b_avgs < b_thresholds).astype(int).tolist()

                                raw_body_bytes = bytearray()
                                for b_idx in range(0, len(cur_body_bits) - 7, 8):
                                    b_val = 0
                                    for bit_idx in range(8):
                                        b_val = (b_val << 1) | cur_body_bits[b_idx + bit_idx]
                                    raw_body_bytes.append(b_val)

                                try:
                                    dec_body_res, _, _ = rsc_body.decode(bytes(raw_body_bytes[:body_fec_len]))
                                    dec_body = bytes(dec_body_res)
                                    break
                                except ReedSolomonError:
                                    continue

                            if dec_body is not None:
                                container_bytes = dec_hdr[:16] + dec_body[:payload_len]
                                secret_text = unpack_qr_container(container_bytes, password)
                                if debug_info is not None:
                                    debug_info["fastPath"] = True
                                    debug_info["ivqrMagicDetected"] = True
                                    debug_info["fecDecoded"] = True
                                    debug_info["failureReason"] = None
                                    debug_info["success"] = True
                                logger.info("[Pass 1 Fast Path] Extraction succeeded directly on raw rectified image!")
                                return public_data, secret_text
    except QRStegoError:
        raise
    except Exception as p1_err:
        logger.debug("[Pass 1 Fast Path] Did not resolve (%s); falling back to Pass 2 heavy recovery", p1_err)

    # ── PASS 2: Heavy Deep Recovery (Adaptive Lanczos + CLAHE + 5x5 Median + K-Means) ──
    # When rectified images are smaller than MIN_RECT_SIZE (e.g. from distant
    # camera crops or low-version QRs), upscale using 3-lobed Lanczos sinc interpolation
    # BEFORE CLAHE and 5x5 median filtering.
    # Calculate current_scale first to prevent NameError, then derive target_scale.
    MIN_RECT_SIZE = 400
    rect_w, rect_h = rectified.size
    current_scale = max(1, round(rect_w / float(qr_size)))

    if rect_w < MIN_RECT_SIZE or rect_h < MIN_RECT_SIZE:
        target_scale = max(current_scale, math.ceil(MIN_RECT_SIZE / float(qr_size)))
        new_w = qr_size * target_scale
        new_h = qr_size * target_scale
        rectified = rectified.resize((new_w, new_h), Image.Resampling.LANCZOS)
        scale = target_scale
        logger.debug(
            "Adaptive LANCZOS upscale applied: %dx%d -> %dx%d (scale=%d, qr_size=%d)",
            rect_w, rect_h, new_w, new_h, scale, qr_size,
        )
    else:
        scale = current_scale

    # ── CLAHE: adaptive tile-based illumination correction ────────────────────
    # Only apply to low-contrast images (typically camera captures with uneven
    # illumination, hot-spots, or screen glare).  High-quality generated QR
    # images already have excellent contrast and must NOT be equalized, as
    # CLAHE would redistribute the subtle 28-lx stego modulation and cause
    # bit-flip errors.  Use the 5th/95th percentile range as a fast estimate.
    CLAHE_CONTRAST_GATE = 80.0  # lx — skip CLAHE above this global contrast
    try:
        rect_arr = np.array(rectified.convert("L"), dtype=np.uint8)
        p5, p95 = np.percentile(rect_arr, [5.0, 95.0])
        global_contrast = float(p95 - p5)
        if global_contrast < CLAHE_CONTRAST_GATE:
            rect_eq = _clahe_numpy(rect_arr, tile_grid=8, clip_limit=2.5)
            rectified = Image.fromarray(rect_eq, mode="L").convert("RGB")
            logger.debug("CLAHE applied (global_contrast=%.1f < %.1f)", global_contrast, CLAHE_CONTRAST_GATE)
        else:
            logger.debug("CLAHE skipped (global_contrast=%.1f >= %.1f)", global_contrast, CLAHE_CONTRAST_GATE)
    except Exception as _clahe_err:
        logger.debug("CLAHE failed, using raw rectified image: %s", _clahe_err)

    # Save processed diagnostic image (after upscale and CLAHE)
    _dump_debug_scan(rectified, "processed")

    # ── Vectorized 5x5 Median Sampling via sliding_window_view ──────────────
    rect_gray = np.array(rectified.convert("L"), dtype=np.uint8)
    padded_rect = np.pad(rect_gray, pad_width=2, mode="edge")
    windows = np.lib.stride_tricks.sliding_window_view(padded_rect, (5, 5))
    centers = (np.arange(qr_size) * scale + (scale // 2)).astype(int)
    sampled_windows = windows[centers[:, None], centers[None, :]]
    module_medians = np.median(sampled_windows, axis=(-2, -1)).astype(np.float32)

    # Collect known unmodulated structural dark and light samples across the entire QR matrix
    struct_dark_pts: List[Tuple[int, int, float]] = []
    struct_light_pts: List[Tuple[int, int, float]] = []

    for r in range(qr_size):
        for c in range(qr_size):
            if (r, c) in structural:
                avg = float(module_medians[r, c])
                if ref_matrix[r][c] == 1:
                    struct_dark_pts.append((r, c, avg))
                else:
                    struct_light_pts.append((r, c, avg))


    # Reject occluded structural points (e.g. from central logos or foreign watermarks)
    if struct_dark_pts and struct_light_pts:
        med_dark = float(np.median([v for _, _, v in struct_dark_pts]))
        med_light = float(np.median([v for _, _, v in struct_light_pts]))
        if med_light > med_dark + 30.0:
            mid = (med_dark + med_light) / 2.0
            struct_dark_pts = [(r, c, v) for (r, c, v) in struct_dark_pts if v < mid]
            struct_light_pts = [(r, c, v) for (r, c, v) in struct_light_pts if v > mid]

    def _fit_plane(pts: List[Tuple[int, int, float]], default_val: float) -> Tuple[float, float, float]:
        if len(pts) >= 3:
            A = np.array([[r, c, 1.0] for (r, c, _) in pts], dtype=float)
            Y = np.array([v for (_, _, v) in pts], dtype=float)
            coeffs, _, _, _ = np.linalg.lstsq(A, Y, rcond=None)
            return float(coeffs[0]), float(coeffs[1]), float(coeffs[2])
        elif pts:
            avg = sum(v for _, _, v in pts) / len(pts)
            return 0.0, 0.0, float(avg)
        return 0.0, 0.0, default_val

    p_dark = _fit_plane(struct_dark_pts, default_val=0.0)
    p_light = _fit_plane(struct_light_pts, default_val=255.0)

    center_r, center_c = qr_size / 2.0, qr_size / 2.0
    dark_at_center = p_dark[0] * center_r + p_dark[1] * center_c + p_dark[2]
    light_at_center = p_light[0] * center_r + p_light[1] * center_c + p_light[2]
    contrast = light_at_center - dark_at_center

    # ── Adaptive effective_delta ──────────────────────────────────────────────
    # When global contrast is low (fog, glare, underexposure), the plane-fit
    # baselines are unreliable and effective_delta collapses near zero, making
    # the bit threshold indistinguishable from sensor noise.  In that regime,
    # fall back to histogram-centroid estimation directly on the rectified image
    # to obtain a more robust dark/light midpoint.
    LOW_CONTRAST_THRESHOLD = 30.0
    if contrast < LOW_CONTRAST_THRESHOLD and struct_dark_pts and struct_light_pts:
        try:
            rect_gray = np.array(rectified.convert("L"), dtype=np.float32)
            dark_vals = np.array([v for _, _, v in struct_dark_pts], dtype=np.float32)
            light_vals = np.array([v for _, _, v in struct_light_pts], dtype=np.float32)
            # Robust centroid: trim the most extreme 10 % from each side
            def _trimmed_mean(arr: np.ndarray, pct: float = 10.0) -> float:
                lo, hi = np.percentile(arr, [pct, 100.0 - pct])
                clipped = arr[(arr >= lo) & (arr <= hi)]
                return float(clipped.mean()) if len(clipped) > 0 else float(arr.mean())
            dark_at_center = _trimmed_mean(dark_vals)
            light_at_center = _trimmed_mean(light_vals)
            contrast = max(LOW_CONTRAST_THRESHOLD, light_at_center - dark_at_center)
            if debug_info is not None:
                debug_info["lowContrastFallback"] = True
        except Exception:
            pass  # keep original plane-fit values

    effective_delta = DARK_MODULATION_DELTA * max(0.08, contrast / 255.0)

    if debug_info is not None:
        debug_info["clientVersion"] = client_version
        debug_info["detectedVersion"] = target_ver
        debug_info["qrDimension"] = qr_size
        debug_info["contrast"] = round(float(contrast), 2)
        debug_info["darkBaseline"] = round(float(dark_at_center), 2)
        debug_info["lightBaseline"] = round(float(light_at_center), 2)
        debug_info["effectiveDelta"] = round(float(effective_delta), 2)
    bleed_factor = min(2.5, max(0.0, (contrast / 255.0) * 2.5))

    # ── K-Means Centroid Estimation on Sampled Dark Module Medians ──────────────
    # Under Nearest-Neighbor upscaling and 1080p streams, sensor noise is preserved
    # as discrete step functions. Non-linear camera ISP tone curves and gamma compression
    # cause the observed modulation delta to diverge from global contrast.
    # We estimate empirical centroids using 1D 2-means clustering on the candidate dark
    # module residuals against the unmodulated structural dark modules (ground truth).
    kmeans_anchor_tf = 0.50
    kmeans_c0_offset = 0.0
    if ordered_dark and struct_dark_pts:
        try:
            # 1. Structural dark modules are 100% unmodulated (ground truth cluster 0)
            struct_res: List[float] = []
            for sr, sc, s_avg in struct_dark_pts:
                s_base = p_dark[0] * sr + p_dark[1] * sc + p_dark[2]
                s_eff_wn = _count_all_white_neighbors(ref_matrix, sr, sc)
                struct_res.append(s_avg - (s_base + s_eff_wn * bleed_factor))

            c0_init = float(np.median(struct_res)) if struct_res else 0.0

            # 2. Candidate dark data modules (mixture of bit 0 and bit 1)
            dark_sample_mods = ordered_dark[:min(256, len(ordered_dark))]
            data_res = np.array([
                float(module_medians[dr, dc]) - (
                    p_dark[0] * dr + p_dark[1] * dc + p_dark[2] +
                    _count_all_white_neighbors(ref_matrix, dr, dc) * bleed_factor
                )
                for dr, dc in dark_sample_mods
            ], dtype=np.float32)

            if len(data_res) >= 16:
                # Initialize c1 from upper quartile or initial effective_delta
                c1_init = max(c0_init + 12.0, float(np.percentile(data_res, 75)))
                c0, c1 = c0_init, c1_init

                # 1D 2-means clustering with L1 (median) updates for outlier robustness
                for _ in range(10):
                    dist0 = np.abs(data_res - c0)
                    dist1 = np.abs(data_res - c1)
                    m1 = dist1 < dist0
                    m0 = ~m1
                    if np.sum(m0) >= 3 and np.sum(m1) >= 3:
                        new_c0 = float(np.median(data_res[m0]))
                        new_c1 = float(np.median(data_res[m1]))
                        if abs(new_c0 - c0) < 0.1 and abs(new_c1 - c1) < 0.1:
                            c0, c1 = new_c0, new_c1
                            break
                        c0, c1 = new_c0, new_c1
                    else:
                        break

                delta_kmeans = c1 - c0
                # A true steganographic signal produces a distinct bimodal separation (delta >= 10 lx)
                if delta_kmeans >= 10.0 and c1 > c0:
                    # Anchor effective_delta directly to empirical cluster distance
                    effective_delta = float(np.clip(delta_kmeans, 12.0, 65.0))
                    # Midpoint decision boundary between the two empirical cluster centroids
                    kmeans_c0_offset = float(c0)
                    kmeans_anchor_tf = 0.50
                    if debug_info is not None:
                        debug_info["kmeansCentroids"] = (round(c0, 2), round(c1, 2))
                        debug_info["kmeansC0Offset"] = round(kmeans_c0_offset, 2)
                        debug_info["kmeansDelta"] = round(delta_kmeans, 2)
                        debug_info["kmeansAnchorTf"] = round(kmeans_anchor_tf, 2)
                        debug_info["effectiveDelta"] = round(effective_delta, 2)
        except Exception as km_err:
            logger.debug("K-Means centroid estimation fallback: %s", km_err)

    _anchor_tf: float = round(kmeans_anchor_tf, 2)

    def _sample_module_bit(r: int, c: int, thresh_factor: float = 0.60) -> int:
        is_dark = (ref_matrix[r][c] == 1)
        base_val = (
            (p_dark[0] * r + p_dark[1] * c + p_dark[2])
            if is_dark
            else (p_light[0] * r + p_light[1] * c + p_light[2])
        )
        eff_wn = _count_all_white_neighbors(ref_matrix, r, c)
        thresh_delta = max(6.0, effective_delta * thresh_factor)
        if is_dark:
            thresh = base_val + (eff_wn * bleed_factor) + kmeans_c0_offset + thresh_delta
        else:
            eff_dn = 5.6 - eff_wn
            thresh = base_val - (eff_dn * bleed_factor * 0.5) - thresh_delta

        avg = float(module_medians[r, c])
        if is_dark:
            return 1 if avg > thresh else 0
        else:
            return 1 if avg < thresh else 0

    def _sample_bits(module_list: Sequence[Tuple[int, int]], thresh_factor: float) -> List[int]:
        if not module_list:
            return []
        rows = np.array([m[0] for m in module_list], dtype=np.intp)
        cols = np.array([m[1] for m in module_list], dtype=np.intp)
        is_dark = np.array([ref_matrix[r][c] == 1 for r, c in module_list], dtype=bool)

        base_vals = np.where(
            is_dark,
            p_dark[0] * rows + p_dark[1] * cols + p_dark[2],
            p_light[0] * rows + p_light[1] * cols + p_light[2],
        )
        eff_wn = np.array([_count_all_white_neighbors(ref_matrix, r, c) for r, c in module_list], dtype=np.float32)
        thresh_delta = max(6.0, effective_delta * thresh_factor)

        thresh_dark = base_vals + (eff_wn * bleed_factor) + kmeans_c0_offset + thresh_delta
        eff_dn = 5.6 - eff_wn
        thresh_light = base_vals - (eff_dn * bleed_factor * 0.5) - thresh_delta
        thresholds = np.where(is_dark, thresh_dark, thresh_light)

        avgs = module_medians[rows, cols]
        bits = np.where(is_dark, avgs > thresholds, avgs < thresholds).astype(int)
        return bits.tolist()

    scan_id = debug_info.get("cameraScanId") if debug_info else None
    debug_capture_enabled = os.getenv("DEBUG_CAMERA_CAPTURE", "false").strip().lower() == "true"

    def _save_debug_vis(candidate_mods: List[Tuple[int, int]], bits_sampled: List[int]):
        if not (scan_id and debug_capture_enabled and rectified is not None):
            return
        try:
            debug_dir = os.path.join("uploads", "debug")
            os.makedirs(debug_dir, exist_ok=True)
            rect_path = os.path.join(debug_dir, f"debug_rectified_qr_{scan_id}.png")
            rect_latest = os.path.join(debug_dir, "debug_rectified_qr_latest.png")
            rectified.save(rect_path)
            rectified.save(rect_latest)

            vis_img = rectified.convert("RGB").copy()
            draw = ImageDraw.Draw(vis_img)
            # Structural markers in cyan
            for sr, sc in structural:
                cx = sc * scale + scale // 2
                cy = sr * scale + scale // 2
                draw.rectangle([cx - 1, cy - 1, cx + 1, cy + 1], fill=(0, 255, 255))
            # Sampled module markers: green if 1, red if 0
            for idx in range(min(len(bits_sampled), len(candidate_mods))):
                mr, mc = candidate_mods[idx]
                bit = bits_sampled[idx]
                cx = mc * scale + scale // 2
                cy = mr * scale + scale // 2
                col = (0, 255, 0) if bit == 1 else (255, 0, 0)
                draw.rectangle([cx - 1, cy - 1, cx + 1, cy + 1], fill=col)

            sampled_path = os.path.join(debug_dir, f"debug_sampled_modules_{scan_id}.png")
            sampled_latest = os.path.join(debug_dir, "debug_sampled_modules_latest.png")
            vis_img.save(sampled_path)
            vis_img.save(sampled_latest)
            logger.debug("Saved debug rectified and sampled module visualizations for %s", scan_id)
        except Exception as v_err:
            logger.debug("Failed to save debug visualizations: %s", v_err)

    # ── PATH 1: 2-Stage Reed-Solomon Forward Error Correction (Low-Bleed Dark Ordering) ──
    hdr_total_fec_bytes = 16 + RS_HEADER_ECC_BYTES  # 24 bytes = 192 bits
    if len(permuted_mods_fec) >= hdr_total_fec_bytes * 8:
        rsc_hdr = RSCodec(RS_HEADER_ECC_BYTES)
        dec_hdr = None
        best_tf = None
        fec_hdr_bits: List[int] = []

        # ── Guided threshold sweep ──────────────────────────────────────────
        # Anchor the sweep on the empirical K-Means cluster midpoint (or dark/light midpoint)
        # and sweep ±0.15 in fine 0.01 steps.
        _anchor_tf = round(kmeans_anchor_tf, 2)
        _guided = [round(_anchor_tf + i * 0.01, 2) for i in range(-15, 16)]
        _guided = [t for t in _guided if 0.12 <= t <= 0.88]
        _coarse = [0.50, 0.55, 0.60, 0.45, 0.40, 0.35, 0.30, 0.25, 0.65, 0.70, 0.75, 0.80]
        candidate_tfs = list(dict.fromkeys(
            [_anchor_tf] + _guided + _coarse
        ))
        for tf in candidate_tfs:
            cur_hdr_bits = _sample_bits(permuted_mods_fec[:hdr_total_fec_bytes * 8], thresh_factor=tf)
            raw_hdr_fec_bytes = bytearray()
            for b_idx in range(0, len(cur_hdr_bits) - 7, 8):
                byte_val = 0
                for bit_idx in range(8):
                    byte_val = (byte_val << 1) | cur_hdr_bits[b_idx + bit_idx]
                raw_hdr_fec_bytes.append(byte_val)

            try:
                dec_hdr_res, _, _ = rsc_hdr.decode(bytes(raw_hdr_fec_bytes))
                res_bytes = bytes(dec_hdr_res)
                if len(res_bytes) >= 16 and res_bytes[:4] == QR_CONTAINER_MAGIC:
                    dec_hdr = res_bytes
                    best_tf = tf
                    fec_hdr_bits = cur_hdr_bits
                    break
            except ReedSolomonError:
                continue

        if dec_hdr is not None:
            magic, version, flags, orig_len, payload_len = struct.unpack(
                ">4sBBII", dec_hdr[:14]
            )
            is_encrypted = bool(flags & 0x01)
            if is_encrypted and not password:
                _save_debug_vis(permuted_mods_fec, fec_hdr_bits)
                if debug_info is not None:
                    debug_info["ivqrMagicDetected"] = True
                    debug_info["failureReason"] = "WRONG_PASSWORD"
                raise QRStegoError(
                    "This QR code is password protected. Please provide the password.",
                    error_code=QRErrorCode.WRONG_PASSWORD,
                )

            rsc_body = RSCodec(RS_BODY_ECC_BYTES)
            body_fec_len = len(rsc_body.encode(b"\x00" * payload_len))
            total_fec_bits = (hdr_total_fec_bytes + body_fec_len) * 8

            if total_fec_bits <= len(permuted_mods_fec):
                _adaptive = (
                    [
                        round(best_tf + i * 0.01, 2)
                        for i in range(-15, 16)
                        if 0.12 <= best_tf + i * 0.01 <= 0.88
                    ]
                    if best_tf is not None
                    else []
                )
                _coarse = [0.60, 0.58, 0.62, 0.55, 0.52, 0.65, 0.50,
                           0.45, 0.40, 0.35, 0.30, 0.25, 0.22, 0.20, 0.18, 0.15,
                           0.70, 0.75, 0.80]
                body_candidate_tfs = list(dict.fromkeys(_adaptive + _coarse))
                dec_body = None
                fec_body_bits: List[int] = []

                for b_tf in body_candidate_tfs:
                    cur_body_bits = _sample_bits(permuted_mods_fec[hdr_total_fec_bytes * 8 : total_fec_bits], thresh_factor=b_tf)
                    raw_body_fec_bytes = bytearray()
                    for b_idx in range(0, len(cur_body_bits) - 7, 8):
                        byte_val = 0
                        for bit_idx in range(8):
                            byte_val = (byte_val << 1) | cur_body_bits[b_idx + bit_idx]
                        raw_body_fec_bytes.append(byte_val)

                    try:
                        dec_body_res, _, _ = rsc_body.decode(bytes(raw_body_fec_bytes[:body_fec_len]))
                        dec_body = bytes(dec_body_res)
                        fec_body_bits = cur_body_bits
                        break
                    except ReedSolomonError:
                        continue

                if dec_body is None:
                    _save_debug_vis(permuted_mods_fec, fec_hdr_bits)
                    if debug_info is not None:
                        debug_info["ivqrMagicDetected"] = True
                        debug_info["failureReason"] = "PAYLOAD_DECODE_FAILED"
                    raise QRStegoError(
                        "InvisioVault secret payload detected, but optical distortion prevented full recovery. Please hold camera steady.",
                        error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED,
                    )

                container_bytes = dec_hdr[:16] + dec_body[:payload_len]
                try:
                    secret_text = unpack_qr_container(container_bytes, password)
                except ValueError as val_err:
                    if "password" in str(val_err).lower() or "tampered" in str(val_err).lower():
                        _save_debug_vis(permuted_mods_fec, fec_hdr_bits + fec_body_bits)
                        if debug_info is not None:
                            debug_info["ivqrMagicDetected"] = True
                            debug_info["failureReason"] = "WRONG_PASSWORD"
                        raise QRStegoError(str(val_err), error_code=QRErrorCode.WRONG_PASSWORD)
                    raise

                _save_debug_vis(permuted_mods_fec, fec_hdr_bits + fec_body_bits)
                if debug_info is not None:
                    debug_info["ivqrMagicDetected"] = True
                    debug_info["fecDecoded"] = True
                    debug_info["failureReason"] = None
                    debug_info["success"] = True
                return public_data, secret_text


    # ── PATH 2: Dark-Priority Non-FEC (Existing QR Codes) ──
    header_bits: List[int] = []
    for idx in range(min(128, len(permuted_mods_dark_priority))):
        r, c = permuted_mods_dark_priority[idx]
        header_bits.append(_sample_module_bit(r, c, thresh_factor=_anchor_tf))

    header_bytes = bytearray()
    for b_idx in range(0, len(header_bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | header_bits[b_idx + bit_idx]
        header_bytes.append(byte_val)

    chosen_permuted_mods = permuted_mods_dark_priority
    is_magic_valid = len(header_bytes) >= 16 and bytes(header_bytes[:4]) == QR_CONTAINER_MAGIC

    # ── PATH 3: Legacy Uniform Non-FEC (Oldest QR Codes) ──
    if not is_magic_valid:
        legacy_header_bits: List[int] = []
        for idx in range(min(128, len(permuted_mods_legacy))):
            r, c = permuted_mods_legacy[idx]
            legacy_header_bits.append(_sample_module_bit(r, c, thresh_factor=_anchor_tf))

        legacy_header_bytes = bytearray()
        for b_idx in range(0, len(legacy_header_bits) - 7, 8):
            byte_val = 0
            for bit_idx in range(8):
                byte_val = (byte_val << 1) | legacy_header_bits[b_idx + bit_idx]
            legacy_header_bytes.append(byte_val)

        if len(legacy_header_bytes) >= 16 and bytes(legacy_header_bytes[:4]) == QR_CONTAINER_MAGIC:
            chosen_permuted_mods = permuted_mods_legacy
            header_bits = legacy_header_bits
            header_bytes = legacy_header_bytes
            is_magic_valid = True

    _save_debug_vis(chosen_permuted_mods, header_bits)

    if debug_info is not None:
        debug_info["ivqrMagicDetected"] = is_magic_valid

    if not is_magic_valid:
        if debug_info is not None:
            if contrast < 8.0:
                debug_info["failureReason"] = "LOW_CONTRAST"
            elif light_at_center > 248.0 and (light_at_center - dark_at_center) > 180.0:
                debug_info["failureReason"] = "OPTICAL_SENSOR_SATURATION"
            else:
                debug_info["failureReason"] = "NO_HIDDEN_DATA"
        return public_data, ""

    magic, version, flags, orig_len, payload_len = struct.unpack(
        ">4sBBII", bytes(header_bytes[:14])
    )
    total_container_len = 16 + payload_len
    total_bits = total_container_len * 8

    if total_bits > len(chosen_permuted_mods):
        if debug_info is not None:
            debug_info["failureReason"] = "MODULE_SAMPLING_FAILURE"
        return public_data, ""

    all_bits = list(header_bits)
    for idx in range(len(header_bits), total_bits):
        r, c = chosen_permuted_mods[idx]
        all_bits.append(_sample_module_bit(r, c, thresh_factor=_anchor_tf))

    container_bytes = bytearray()
    for b_idx in range(0, len(all_bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | all_bits[b_idx + bit_idx]
        container_bytes.append(byte_val)

    try:
        secret_text = unpack_qr_container(bytes(container_bytes[:total_container_len]), password)
    except ValueError as e:
        if "password" in str(e).lower() or "tampered" in str(e).lower():
            if debug_info is not None:
                debug_info["failureReason"] = "WRONG_PASSWORD"
            raise QRStegoError(str(e), error_code=QRErrorCode.WRONG_PASSWORD)
        if debug_info is not None:
            debug_info["failureReason"] = "CRC_FAILURE"
        raise QRStegoError(str(e), error_code=QRErrorCode.HIDDEN_PAYLOAD_CORRUPTED)

    if debug_info is not None:
        debug_info["failureReason"] = None
        debug_info["success"] = True

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

    if int(qr.version) > MAX_SAFE_QR_VERSION:
        raise QRStegoError(
            f"Hidden payload exceeds safe QR capacity (requires version {qr.version}, "
            f"maximum safe version is {MAX_SAFE_QR_VERSION}).",
            error_code=QRErrorCode.CAPACITY_EXCEEDED,
        )

    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=scale, dark=fg_color, light=bg_color, border=border)
    buf.seek(0)

    with Image.open(buf) as tmp_img:
        rgb_img = tmp_img.convert("RGB")
        try:
            if logo_path:
                _embed_logo_image(rgb_img, logo_path, border=border, scale=scale)
            rgb_img.save(output_path, "PNG", optimize=False, compress_level=6)
        finally:
            rgb_img.close()

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
    scale = max(5, min(30, scale))

    # Determine embedding strategy
    chosen_method = method.lower()
    if chosen_method == "stream":
        raise QRStegoError(
            "Stream QR generation is no longer supported. InvisioVault generates clean visual steganographic QR codes.",
            error_code=QRErrorCode.QR_INVALID,
        )

    if chosen_method in ("auto", "visual"):
        chosen_method = "visual"
    else:
        raise QRStegoError(
            f"Unsupported QR generation method '{method}'. InvisioVault generates clean visual steganographic QR codes.",
            error_code=QRErrorCode.QR_INVALID,
        )

    logger.info(
        "Generating visual QR steganography (public_len=%d, secret_len=%d)",
        len(public_data), len(secret_text)
    )

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


def extract_from_qr_stego(
    qr_path: str,
    password: Optional[str] = None,
    raw_qr_text: Optional[str] = None,
    client_corners: Optional[Dict[str, Any]] = None,
    client_version: Optional[int] = None,
    debug_info: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Extract visible data and hidden secret from a QR code image.

    Implements a multi-stage robust extraction pipeline:
      0. Client-assisted decode: If raw_qr_text contains #IVDATA:, decode immediately.
      1. Priority geometry resolution:
         - Client jsQR corners (measured on the exact frame submitted)
         - Server-side zxing-cpp corners
         - PyZbar polygon fallback
      2. Check stream mode (#IVDATA: fragment).
      3. Perspective-correct visual layer extraction with 2D illumination surface fitting.
      4. Validate IVQR container integrity, decrypt and decompress.
      5. Return (public_data, secret_text).

    Args:
        qr_path:        Path to QR code image.
        password:       Decryption password if the secret was sealed with one.
        raw_qr_text:    Optional decoded QR string from client-side scanner.
        client_corners: Optional corner coordinates {topLeftCorner, ...} from client jsQR.
        client_version: Optional QR version integer from client jsQR.
        debug_info:     Optional dictionary to receive structured diagnostic metrics.

    Returns:
        (public_data, secret_text)

    Raises:
        QRStegoError: On missing QR, wrong password, or corrupted data.
    """
    try:
        logger.info(
            "Extracting from QR code: %s (has_raw_text=%s, has_client_corners=%s)",
            qr_path,
            bool(raw_qr_text),
            bool(client_corners),
        )

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

        if isinstance(qr_path, (str, os.PathLike)):
            if not os.path.exists(qr_path):
                raise QRStegoError(
                    f"QR code file not found: {qr_path}",
                    error_code=QRErrorCode.QR_NOT_DETECTED,
                )
            img_source = qr_path
        else:
            img_source = qr_path

        with Image.open(img_source) as raw_img:
            img = raw_img.copy()
            if img.mode in ("RGBA", "LA", "P"):
                img = img.convert("RGBA")
                background = Image.new("RGBA", img.size, (255, 255, 255, 255))
                background.paste(img, mask=img.split()[3])
                img = background.convert("L")
            else:
                img = img.convert("L")

        parsed_client_pos = _parse_client_corners(client_corners)

        # Coordinate scale validation if client corners are provided
        if parsed_client_pos is not None:
            pts = [
                (parsed_client_pos.top_left.x, parsed_client_pos.top_left.y),
                (parsed_client_pos.bottom_left.x, parsed_client_pos.bottom_left.y),
                (parsed_client_pos.bottom_right.x, parsed_client_pos.bottom_right.y),
                (parsed_client_pos.top_right.x, parsed_client_pos.top_right.y),
            ]
            img_w, img_h = img.size
            out_of_bounds = any(x < -15.0 or y < -15.0 or x > img_w + 15.0 or y > img_h + 15.0 for x, y in pts)
            if out_of_bounds:
                if debug_info is not None:
                    debug_info["coordinateScaleValid"] = False
                    debug_info["failureReason"] = "BAD_COORDINATE_SCALE"
                    logger.warning("QR scan [%s]: Client corners out of bounds for image %dx%d: %s",
                                   debug_info.get("cameraScanId"), img_w, img_h, pts)
            else:
                if debug_info is not None:
                    debug_info["coordinateScaleValid"] = True
        elif client_corners is not None and debug_info is not None:
            debug_info["failureReason"] = "NO_CLIENT_GEOMETRY"

        # Priority 1: Client geometry from exact same frame (if provided with decoded text)
        client_attempted = False
        client_failure_reason = None
        if parsed_client_pos is not None and raw_qr_text:
            client_attempted = True
            if debug_info is not None:
                debug_info["geometrySource"] = "client_jsqr"
            try:
                pub, sec = _extract_visual_qr(
                    img,
                    parsed_client_pos,
                    raw_qr_text,
                    password=password,
                    client_version=client_version,
                    debug_info=debug_info,
                )
                if sec:
                    logger.info(
                        "Visual extraction complete from client geometry. Public: %d chars, Secret: %d chars.",
                        len(pub),
                        len(sec),
                    )
                    return pub, sec
                client_failure_reason = debug_info.get("failureReason") if debug_info else None
            except QRStegoError:
                raise
            except Exception as exc:
                logger.debug("Visual extraction using client corners produced no payload: %s", exc)
                client_failure_reason = "EXTRACTION_EXCEPTION"

        # Priority 2: Server-side detection via zxing-cpp
        decoded_objects = []
        try:
            read_kwargs: Dict[str, Any] = {"try_rotate": True, "try_downscale": True}
            binarizer_cls = getattr(zxingcpp, "Binarizer", None)
            if binarizer_cls is not None and hasattr(binarizer_cls, "LocalAverage"):
                read_kwargs["binarizer"] = binarizer_cls.LocalAverage
            decoded_objects = zxingcpp.read_barcodes(img, **read_kwargs)
        except Exception as exc:
            logger.debug("zxingcpp read failed: %s, falling back to pyzbar", exc)

        position = None
        qr_text = ""

        if decoded_objects:
            qr_text = getattr(decoded_objects[0], "text", "")
            position = getattr(decoded_objects[0], "position", None)
            if debug_info is not None and not client_attempted:
                debug_info["geometrySource"] = "server_zxing"
        else:
            # Fallback to pyzbar if available
            pyz_res = pyzbar.decode(img) if pyzbar is not None else None
            if pyz_res:
                qr_text = pyz_res[0].data.decode("utf-8", errors="replace")
                if hasattr(pyz_res[0], "polygon") and len(pyz_res[0].polygon) == 4:
                    poly = pyz_res[0].polygon
                    position = QRPosition(poly[0], poly[1], poly[2], poly[3])
                if debug_info is not None and not client_attempted:
                    debug_info["geometrySource"] = "server_pyzbar"
            elif raw_qr_text:
                qr_text = raw_qr_text
                position = parsed_client_pos
                if debug_info is not None and not client_attempted:
                    debug_info["geometrySource"] = "client_fallback"
            else:
                if debug_info is not None:
                    debug_info["failureReason"] = "NO_QR"
                raise QRStegoError(
                    "No QR code found in the image.",
                    error_code=QRErrorCode.QR_NOT_DETECTED,
                )

        # Diagnostic consistency check between client raw_qr_text and server qr_text
        if debug_info is not None:
            if raw_qr_text and qr_text:
                if raw_qr_text == qr_text:
                    debug_info["consistency"] = "CONSISTENT"
                else:
                    debug_info["consistency"] = "DATA_MISMATCH"
            elif raw_qr_text and not decoded_objects:
                debug_info["consistency"] = "UNVERIFIED_SERVER_DECODER"

        # Check Stream Mode (#IVDATA:)
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

        # Check Visual Module Layer with server position
        if position is not None:
            try:
                pub, sec = _extract_visual_qr(
                    img,
                    position,
                    qr_text,
                    password=password,
                    client_version=client_version,
                    debug_info=debug_info,
                )
                if sec:
                    logger.info(
                        "Extraction complete from server position. Public: %d chars, Secret: %d chars.",
                        len(pub),
                        len(sec),
                    )
                    return pub, sec
            except QRStegoError:
                raise
            except Exception as exc:
                logger.debug("Visual extraction check produced no payload: %s", exc)

        # Fallback to client geometry if server position did not recover payload
        if parsed_client_pos is not None and position != parsed_client_pos:
            try:
                pub, sec = _extract_visual_qr(
                    img,
                    parsed_client_pos,
                    qr_text,
                    password=password,
                    client_version=client_version,
                    debug_info=debug_info,
                )
                if sec:
                    logger.info(
                        "Extraction complete from fallback client geometry. Public: %d chars, Secret: %d chars.",
                        len(pub),
                        len(sec),
                    )
                    return pub, sec
            except QRStegoError:
                raise
            except Exception as exc:
                logger.debug("Fallback client geometry produced no payload: %s", exc)

        # Regular QR code without hidden data
        if debug_info is not None:
            if client_attempted:
                debug_info["geometrySource"] = "client_jsqr"
                debug_info["failureReason"] = client_failure_reason or "NO_HIDDEN_DATA"
            elif not debug_info.get("failureReason"):
                debug_info["failureReason"] = "NO_HIDDEN_DATA"
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
