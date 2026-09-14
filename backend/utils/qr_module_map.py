"""QR Module Mapping and Spatial Distribution Utilities.

This module enforces ISO/IEC 18004 structural module isolation.
It maps and protects:
  - Finder patterns (7x7) + Separators (1 module white border)
  - Timing patterns (row 6, column 6)
  - Alignment patterns (5x5 patterns according to version table)
  - Format information areas (15 bits around finders)
  - Version information blocks (for version >= 7)
  - Dark module at (4*version + 9, 8)
  - Quiet zone (>= 4 modules)

It extracts the exact set of non-structural "safe data modules" eligible for
steganographic embedding, and provides deterministic pseudo-random permutation
to distribute modifications uniformly across the QR matrix, avoiding clusters
or runs.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
from typing import List, Optional, Set, Tuple

import numpy as np
from PIL import Image
import segno.consts as consts


def get_qr_dimension(version: int) -> int:
    """Return width/height in modules for standard QR version (1 <= version <= 40)."""
    if not (1 <= version <= 40):
        raise ValueError(f"QR version must be between 1 and 40, got {version}")
    return 17 + 4 * version


def get_structural_modules(version: int) -> Set[Tuple[int, int]]:
    """Return the set of (row, col) coordinates for all structural QR modules.

    Args:
        version: QR version (1 to 40).

    Returns:
        Set of (r, c) module coordinates that must NOT be modified.
    """
    size = get_qr_dimension(version)
    structural: Set[Tuple[int, int]] = set()

    # 1. Finder patterns (7x7) + Separators (1 module border) -> 8x8 corner regions
    # Top-left corner: rows 0..8, cols 0..8
    for r in range(9):
        for c in range(9):
            structural.add((r, c))

    # Top-right corner: rows 0..8, cols (size - 8)..size - 1
    for r in range(9):
        for c in range(size - 8, size):
            structural.add((r, c))

    # Bottom-left corner: rows (size - 8)..size - 1, cols 0..8
    for r in range(size - 8, size):
        for c in range(9):
            structural.add((r, c))

    # 2. Timing patterns: row 6 and column 6
    for i in range(size):
        structural.add((6, i))
        structural.add((i, 6))

    # 3. Alignment patterns (version >= 2)
    if version >= 2:
        positions = consts.ALIGNMENT_POS[version - 2]
        min_pos = positions[0]
        max_pos = positions[-1]
        finder_centers = {(min_pos, min_pos), (min_pos, max_pos), (max_pos, min_pos)}
        for x in positions:
            for y in positions:
                if (x, y) in finder_centers:
                    continue
                # Alignment pattern is 5x5 centered at (x, y)
                for dr in range(-2, 3):
                    for dc in range(-2, 3):
                        structural.add((x + dr, y + dc))

    # 4. Version information areas (version >= 7)
    # Two 3x6 rectangles:
    #   - Upper-right: rows 0..5, cols (size - 11)..(size - 9)
    #   - Lower-left: rows (size - 11)..(size - 9), cols 0..5
    if version >= 7:
        for r in range(6):
            for c in range(size - 11, size - 8):
                structural.add((r, c))
        for r in range(size - 11, size - 8):
            for c in range(6):
                structural.add((r, c))

    # 5. Required Dark Module: always at row (4*version + 9), col 8
    dark_row = 4 * version + 9
    structural.add((dark_row, 8))

    return structural


def get_safe_data_modules(version: int) -> List[Tuple[int, int]]:
    """Return an ordered list of safe data module coordinates (row, col).

    Args:
        version: QR version (1 to 40).

    Returns:
        List of safe (r, c) tuples that are free for steganographic embedding.
    """
    size = get_qr_dimension(version)
    structural = get_structural_modules(version)
    safe: List[Tuple[int, int]] = []
    for r in range(size):
        for c in range(size):
            if (r, c) not in structural:
                safe.append((r, c))
    return safe


def deterministic_permute(items: list, seed: bytes) -> list:
    """Deterministically permute a list using an HMAC-SHA256 Fisher-Yates shuffle.

    Args:
        items: List of items to shuffle.
        seed:  Cryptographic seed (e.g., hash of public payload + matrix params).

    Returns:
        New list with items permuted deterministically.
    """
    n = len(items)
    result = list(items)
    counter = 0
    for i in range(n - 1, 0, -1):
        h = hmac.new(seed, struct.pack(">I", counter), hashlib.sha256).digest()
        counter += 1
        rand_val = struct.unpack(">I", h[:4])[0]
        j = rand_val % (i + 1)
        result[i], result[j] = result[j], result[i]
    return result


def _verify_finder_pattern(rect: Image.Image, r0: int, c0: int, scale: int = 10) -> bool:
    """Verify standard 7x7 concentric finder pattern at (r0, c0)."""
    # Center 3x3 must be dark: (r0+2..r0+4, c0+2..c0+4)
    for dr in range(2, 5):
        for dc in range(2, 5):
            px = rect.getpixel(((c0 + dc) * scale + scale // 2, (r0 + dr) * scale + scale // 2))
            luma = px[0] if isinstance(px, tuple) else px
            if luma > 140:
                return False

    # Ring around center must be light: (r0+1, c0+1..5), (r0+5, c0+1..5)
    for dc in range(1, 6):
        px1 = rect.getpixel(((c0 + dc) * scale + scale // 2, (r0 + 1) * scale + scale // 2))
        px2 = rect.getpixel(((c0 + dc) * scale + scale // 2, (r0 + 5) * scale + scale // 2))
        l1 = px1[0] if isinstance(px1, tuple) else px1
        l2 = px2[0] if isinstance(px2, tuple) else px2
        if l1 < 115 or l2 < 115:
            return False

    return True


def detect_qr_version_from_timing(
    img: Image.Image,
    position,
    scale: int = 10,
    min_version: int = 1,
) -> Tuple[Optional[int], Optional[Image.Image]]:
    """Determine the exact QR version by evaluating finder patterns and timing patterns.

    Rectifies candidate version grids using the detected barcode bounding
    quadrilateral, verifies structural finder pattern alignment at top-right and
    bottom-left, and checks timing pattern module alternations on row 6.

    Args:
        img:         Pillow image containing the QR code.
        position:    Barcode position object from zxing-cpp.
        scale:       Pixel sampling scale factor (default 10).
        min_version: Minimum candidate QR version based on public data length.

    Returns:
        (best_version, rectified_image) or (None, None) if unresolved.
    """
    quad = (
        position.top_left.x, position.top_left.y,
        position.bottom_left.x, position.bottom_left.y,
        position.bottom_right.x, position.bottom_right.y,
        position.top_right.x, position.top_right.y
    )
    best_ver: Optional[int] = None
    best_score = -1.0
    best_rect: Optional[Image.Image] = None

    for ver in range(max(1, min_version), 41):
        size = get_qr_dimension(ver)
        rect_dim = size * scale
        rect = img.transform((rect_dim, rect_dim), Image.Transform.QUAD, quad)

        # 1. Structural Finder Pattern Verification:
        # Top-right finder is at (0, size - 7); Bottom-left finder is at (size - 7, 0)
        if not _verify_finder_pattern(rect, 0, size - 7, scale):
            continue
        if not _verify_finder_pattern(rect, size - 7, 0, scale):
            continue

        # 2. Timing pattern along row 6 between column 8 and column (size - 9)
        correct = 0
        total = size - 16
        if total <= 0:
            best_ver = ver
            best_rect = rect
            break

        for c in range(8, size - 8):
            expected = 1 if (c % 2 == 0) else 0
            px_val = rect.getpixel((c * scale + scale // 2, 6 * scale + scale // 2))
            luma = px_val[0] if isinstance(px_val, tuple) else px_val
            detected = 1 if luma < 128 else 0
            if detected == expected:
                correct += 1

        score = correct / total
        if score > best_score:
            best_score = score
            best_ver = ver
            best_rect = rect
            if score >= 0.90:  # Confirmed match
                break

    if best_ver is None:
        return None, None

    return best_ver, best_rect
