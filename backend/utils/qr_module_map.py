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
from typing import Dict, List, Optional, Sequence, Set, Tuple

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

    # 6. Center reservation (protects center area up to 15% width from data modulation,
    # ensuring that centered logos do not overwrite or corrupt steganographic bits)
    center = size // 2
    logo_mod_radius = math.ceil((size + 8) * 0.15 / 2) + 1
    for r in range(max(0, center - logo_mod_radius), min(size, center + logo_mod_radius + 1)):
        for c in range(max(0, center - logo_mod_radius), min(size, center + logo_mod_radius + 1)):
            structural.add((r, c))

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


def _get_pixel_luma(img: Image.Image, x: int, y: int) -> float:
    """Safely sample pixel luminance from image, handling tuple, scalar, and None."""
    px = img.getpixel((x, y))
    if isinstance(px, tuple):
        return float(px[0])
    if px is not None:
        return float(px)
    return 0.0


def verify_finder_pattern(
    rect: Image.Image,
    r0: int,
    c0: int,
    scale: int = 10,
    min_contrast: float = 10.0,
) -> Tuple[bool, float]:
    """Verify standard 7x7 concentric finder pattern at (r0, c0) using relative contrast.

    Returns:
        (is_valid, threshold) where threshold is the estimated dark/light midpoint.
    """
    # Center 3x3 must be dark: (r0+2..r0+4, c0+2..c0+4)
    center_samples: List[float] = []
    for dr in range(2, 5):
        for dc in range(2, 5):
            center_samples.append(
                _get_pixel_luma(rect, (c0 + dc) * scale + scale // 2, (r0 + dr) * scale + scale // 2)
            )

    # Ring around center must be light: (r0+1, c0+1..5), (r0+5, c0+1..5) and vertical edges
    ring_samples: List[float] = []
    for dc in range(1, 6):
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + dc) * scale + scale // 2, (r0 + 1) * scale + scale // 2)
        )
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + dc) * scale + scale // 2, (r0 + 5) * scale + scale // 2)
        )
    for dr in range(2, 5):
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + 1) * scale + scale // 2, (r0 + dr) * scale + scale // 2)
        )
        ring_samples.append(
            _get_pixel_luma(rect, (c0 + 5) * scale + scale // 2, (r0 + dr) * scale + scale // 2)
        )

    avg_center = sum(center_samples) / len(center_samples)
    avg_ring = sum(ring_samples) / len(ring_samples)

    # Ring must be lighter than dark center (relative contrast >= min_contrast)
    if avg_ring - avg_center < min_contrast:
        fallback_th = (avg_center + avg_ring) / 2.0 if avg_ring > avg_center else 128.0
        return False, fallback_th

    return True, (avg_center + avg_ring) / 2.0


_verify_finder_pattern = verify_finder_pattern


def find_perspective_coeffs(
    src_pts: Sequence[Tuple[float, float]],
    dst_pts: Sequence[Tuple[float, float]],
) -> np.ndarray:
    """Compute 8-element perspective transform coefficients for Pillow.

    Maps destination coordinates (xd, yd) to source image coordinates (xs, ys):
        xs = (a * xd + b * yd + c) / (g * xd + h * yd + 1)
        ys = (d * xd + e * yd + f) / (g * xd + h * yd + 1)

    Args:
        src_pts: 4 source points [TL, BL, BR, TR] in the input image.
        dst_pts: 4 destination points [TL, BL, BR, TR] in canonical rectangle.

    Returns:
        8-element 1D numpy array (a, b, c, d, e, f, g, h).
    """
    matrix = []
    for (xd, yd), (xs, ys) in zip(dst_pts, src_pts):
        matrix.append([xd, yd, 1.0, 0.0, 0.0, 0.0, -xs * xd, -xs * yd])
        matrix.append([0.0, 0.0, 0.0, xd, yd, 1.0, -ys * xd, -ys * yd])
    A = np.asarray(matrix, dtype=float)
    B = np.asarray(src_pts, dtype=float).reshape(8)
    coeffs, _, _, _ = np.linalg.lstsq(A, B, rcond=None)
    return coeffs.reshape(8)


def get_pattern_centers(version: int) -> Dict[str, Tuple[float, float]]:
    """Return canonical (x, y) coordinates of finder and bottom-right alignment centers in module units."""
    size = get_qr_dimension(version)
    centers = {
        "top_left_finder": (3.5, 3.5),
        "bottom_left_finder": (3.5, size - 3.5),
        "top_right_finder": (size - 3.5, 3.5),
    }
    if version >= 2:
        align_pos = consts.ALIGNMENT_POS[version - 2][-1]
        centers["bottom_right_alignment"] = (align_pos + 0.5, align_pos + 0.5)
    return centers


def detect_qr_version_from_timing(
    img: Image.Image,
    position,
    scale: int = 10,
    min_version: int = 1,
    target_version_hint: Optional[int] = None,
) -> Tuple[Optional[int], Optional[Image.Image]]:
    """Determine the exact QR version by evaluating finder patterns and timing patterns.

    Rectifies candidate version grids using true projective homography (perspective
    transform) from the detected barcode quadrilateral, verifies structural finder
    pattern alignment at top-right and bottom-left, and checks alternating timing
    patterns on row 6 and column 6.

    Args:
        img:                 Pillow image containing the QR code.
        position:            Barcode position object with top_left, bottom_left,
                             bottom_right, and top_right attributes (and optional
                             pattern centroids).
        scale:               Pixel sampling scale factor (default 10).
        min_version:         Minimum candidate QR version based on public data length.
        target_version_hint: Optional candidate version from client detector.

    Returns:
        (best_version, rectified_image) or (None, None) if unresolved.
    """
    src_pts_outer = [
        (float(position.top_left.x), float(position.top_left.y)),
        (float(position.bottom_left.x), float(position.bottom_left.y)),
        (float(position.bottom_right.x), float(position.bottom_right.y)),
        (float(position.top_right.x), float(position.top_right.y)),
    ]

    best_ver: Optional[int] = None
    best_score = -1.0
    best_rect: Optional[Image.Image] = None

    # Prioritize target_version_hint if provided and valid
    candidate_versions: List[int] = []
    if target_version_hint is not None and max(1, min_version) <= target_version_hint <= 40:
        candidate_versions.append(target_version_hint)
    for ver in range(max(1, min_version), 41):
        if ver not in candidate_versions:
            candidate_versions.append(ver)

    for ver in candidate_versions:
        size = get_qr_dimension(ver)
        rect_dim = size * scale

        tl_f = getattr(position, "top_left_finder", None)
        bl_f = getattr(position, "bottom_left_finder", None)
        br_a = getattr(position, "bottom_right_alignment", None)
        tr_f = getattr(position, "top_right_finder", None)

        use_patterns = (
            ver >= 2
            and tl_f is not None
            and bl_f is not None
            and br_a is not None
            and tr_f is not None
        )

        if use_patterns and tl_f is not None and bl_f is not None and br_a is not None and tr_f is not None:
            align_pos = consts.ALIGNMENT_POS[ver - 2][-1]
            src_pts = [
                (float(tl_f.x), float(tl_f.y)),
                (float(bl_f.x), float(bl_f.y)),
                (float(br_a.x), float(br_a.y)),
                (float(tr_f.x), float(tr_f.y)),
            ]
            dst_pts = [
                (3.5 * scale, 3.5 * scale),
                (3.5 * scale, (size - 3.5) * scale),
                ((align_pos + 0.5) * scale, (align_pos + 0.5) * scale),
                ((size - 3.5) * scale, 3.5 * scale),
            ]
        else:
            src_pts = src_pts_outer
            dst_pts = [
                (0.0, 0.0),
                (0.0, float(rect_dim)),
                (float(rect_dim), float(rect_dim)),
                (float(rect_dim), 0.0),
            ]

        coeffs = find_perspective_coeffs(src_pts, dst_pts)
        try:
            rect = img.transform(
                (rect_dim, rect_dim),
                Image.Transform.PERSPECTIVE,
                coeffs.tolist(),  # PIL expects Sequence, not ndarray
                Image.Resampling.LANCZOS,
            )
        except ValueError:
            # Pillow's C engine only permits NEAREST (0), BILINEAR (2), or BICUBIC (3) for PERSPECTIVE transform.
            rect = img.transform(
                (rect_dim, rect_dim),
                Image.Transform.PERSPECTIVE,
                coeffs.tolist(),
                Image.Resampling.BICUBIC,
            )

        # 1. Structural Finder Pattern Verification:
        # Top-right finder is at (0, size - 7); Bottom-left finder is at (size - 7, 0)
        is_hint = (target_version_hint is not None and ver == target_version_hint)
        min_c = 4.0 if is_hint else 10.0
        ok_tr, th_tr = _verify_finder_pattern(rect, 0, size - 7, scale, min_contrast=min_c)
        if not ok_tr and not is_hint:
            continue
        ok_bl, th_bl = _verify_finder_pattern(rect, size - 7, 0, scale, min_contrast=min_c)
        if not ok_bl and not is_hint:
            continue

        timing_threshold: float = (th_tr + th_bl) / 2.0
        if is_hint and best_rect is None:
            best_ver = ver
            best_rect = rect

        # 2. Timing pattern along row 6 and column 6
        correct = 0
        total = (size - 16) * 2
        if total <= 0:
            best_ver = ver
            best_rect = rect
            break

        for c in range(8, size - 8):
            expected = 1 if (c % 2 == 0) else 0
            luma = _get_pixel_luma(rect, c * scale + scale // 2, 6 * scale + scale // 2)
            detected = 1 if luma < timing_threshold else 0
            if detected == expected:
                correct += 1

        for r in range(8, size - 8):
            expected = 1 if (r % 2 == 0) else 0
            luma = _get_pixel_luma(rect, 6 * scale + scale // 2, r * scale + scale // 2)
            detected = 1 if luma < timing_threshold else 0
            if detected == expected:
                correct += 1

        score = correct / total
        if score > best_score:
            best_score = score
            best_ver = ver
            best_rect = rect
            if score >= 0.80:  # Confirmed match
                break

    if best_ver is None:
        return None, None

    return best_ver, best_rect
