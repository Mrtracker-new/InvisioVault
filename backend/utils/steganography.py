"""Steganography utilities for hiding and extracting files in images.

Wire format — v1 (legacy, still supported for extraction)
---------------------------------------------------------
Without password:
    [password_flag(1)=0x00] [metadata_length(2, BE)] [metadata: "filename|mime"(N)] [data_length(4, BE)] [compressed_data(M)]

With password:
    [password_flag(1)=0x01] [salt(16)] [metadata_length(2, BE)] [enc_metadata(N)] [data_length(4, BE)] [enc_payload(M)]

Wire format — v2 (current writer, introduced to fix M-06)
---------------------------------------------------------
A v2 blob always starts with the two-byte magic sequence 0xFF 0x02, which is
unambiguous because v1 password_flag is only ever 0x00 or 0x01.

Without password:
    [MAGIC(2)=0xFF 0x02] [password_flag(1)=0x00] [metadata_length(4, BE)] [metadata: "filename|mime"(N)] [data_length(4, BE)] [compressed_data(M)]

With password:
    [MAGIC(2)=0xFF 0x02] [password_flag(1)=0x01] [salt(16)] [metadata_length(4, BE)] [enc_metadata(N)] [data_length(4, BE)] [enc_payload(M)]

Migration notes
---------------
* All NEW embeds are written in v2 format.
* Extraction transparently handles both v1 and v2 blobs, so previously
  embedded images continue to work without any re-encoding.
* The upgrade from 2-byte to 4-byte metadata_length closes the OverflowError
  DoS vector (M-06) and future-proofs the field (max 4 GiB vs 64 KiB).

    enc_metadata  = Fernet(key).encrypt(b"filename|mime")
    enc_payload   = Fernet(key).encrypt(compressed_data)

Both metadata_length and data_length encode the length of the *ciphertext*
(not plaintext) so that the reader can use them as exact byte-counts without
knowing the password.
"""
from __future__ import annotations

from PIL import Image
import zlib
import mimetypes
import os
import secrets
from cryptography.fernet import Fernet
import base64
import itertools

from utils.crypto_utils import derive_fernet_key


# ── Wire-format constants ──────────────────────────────────────────────────────

# Magic header that distinguishes a v2 blob from a legacy v1 blob.
# 0xFF is never a valid v1 password_flag (only 0x00 / 0x01 are), so this is an
# unambiguous discriminator that requires zero guessing on the read side.
_V2_MAGIC: bytes = b"\xff\x02"

# Byte widths of the length fields.
_V1_META_LEN_BYTES: int = 2   # legacy: 2-byte metadata_length   → max 65 535 B
_V2_META_LEN_BYTES: int = 4   # current: 4-byte metadata_length  → max 4 GiB
_DATA_LEN_BYTES:    int = 4   # payload length field (unchanged)


# ── Safety caps ───────────────────────────────────────────────────────────────

# Maximum metadata *plaintext* we will ever embed.  No legitimate filename +
# MIME string should exceed this.  Enforced at write time before any length
# serialisation so OverflowError can never reach to_bytes().
_MAX_METADATA_PLAIN_LEN: int = 512

# When a password is used the metadata field holds a Fernet ciphertext.
# Fernet overhead: 1-byte version + 8-byte timestamp + 16-byte IV + 32-byte
# HMAC = 57 bytes of overhead, then base64url-encoded in 4/3 ratio.
# Upper bound: ceil((512 + 57) / 3) * 4 = 760 bytes.  We use 1024 for headroom.
_MAX_METADATA_ENC_LEN: int = 1_024

# Absolute hard cap on raw (compressed / encrypted) payload bytes we will ever
# materialise from a single image.  100 MB.
_MAX_PAYLOAD_BYTES: int = 100 * 1_024 * 1_024

# Sanity assertion: our caps must fit inside the v2 4-byte field.
# This fires at module-import time if someone accidentally reduces the field
# width back to 2 bytes without adjusting the caps.
assert _MAX_METADATA_PLAIN_LEN <= 0xFFFF_FFFF, "metadata plain cap overflows 4-byte field"
assert _MAX_METADATA_ENC_LEN   <= 0xFFFF_FFFF, "metadata enc cap overflows 4-byte field"
assert _MAX_PAYLOAD_BYTES      <= 0xFFFF_FFFF, "payload cap overflows 4-byte field"


# Key derivation is provided by the shared crypto_utils module.
# ``derive_fernet_key(password, salt)`` is a drop-in replacement for the old
# ``_derive_key_from_password`` — same algorithm, same output format.
_derive_key_from_password = derive_fernet_key  # backwards-compat alias


# ── Streaming LSB primitives ───────────────────────────────────────────────────

def _iter_lsb_bytes(img: Image.Image):
    """Yield each LSB byte extracted from the RGB channels without ever
    materialising the entire pixel list in Python memory.

    Pillow's ``ImagingCore`` object (returned by ``img.getdata()``) supports
    direct integer indexing, so we can walk it sequentially without converting
    it to a Python list.  Peak additional memory is O(1) — just one pixel
    tuple per iteration step.

    Yields:
        int: the next reconstructed byte (0–255) from the image's LSBs.
    """
    data = img.getdata()           # ImagingCore — C-backed, NOT a Python list
    total = img.width * img.height # pixel count — zero allocation
    byte = 0
    bit_count = 0
    for idx in range(total):
        pixel = data[idx]
        for ch in pixel[:3]:      # R, G, B only
            byte = (byte << 1) | (ch & 1)
            bit_count += 1
            if bit_count == 8:
                yield byte
                byte = 0
                bit_count = 0


def _read_exactly(gen, n: int, context: str = "data") -> bytes:
    """Consume exactly *n* bytes from *gen*, raising ValueError on underflow.

    Args:
        gen: byte generator (e.g. from :func:`_iter_lsb_bytes`)
        n:   number of bytes to read
        context: human-readable label used in the error message

    Returns:
        bytes of length *n*
    """
    buf = bytes(itertools.islice(gen, n))
    if len(buf) < n:
        raise ValueError(
            f"Image is too small or does not contain valid hidden data "
            f"(tried to read {n} bytes of {context}, got {len(buf)})."
        )
    return buf


# ── Internal helpers ───────────────────────────────────────────────────────────

def _encode_metadata_length(n: int) -> bytes:
    """Serialise *n* as a 4-byte big-endian unsigned integer (v2 writer).

    Raises:
        ValueError: if *n* exceeds _MAX_METADATA_ENC_LEN (fail-fast defence
                    against future cap-constant mismatches).
        OverflowError: if *n* somehow exceeds 2**32-1 (Python will raise this
                       natively; we document it for clarity).
    """
    # Explicit cap check: converts a future OverflowError 500 into a clear
    # ValueError 400 with a developer-friendly message.
    if n > _MAX_METADATA_ENC_LEN:
        raise ValueError(
            f"Metadata field length ({n} B) exceeds the maximum allowed "
            f"{_MAX_METADATA_ENC_LEN} B.  Reduce the filename length."
        )
    # With _MAX_METADATA_ENC_LEN ≤ 0xFFFF_FFFF (asserted at module load), this
    # to_bytes() call is guaranteed to succeed — the assertion above is the
    # true safety net; the to_bytes() width is just headroom.
    return n.to_bytes(_V2_META_LEN_BYTES, "big")


# ── Public API ─────────────────────────────────────────────────────────────────

def hide_file_in_image(
    image_path: str,
    file_path: str,
    output_path: str,
    password: str = None,
) -> str:
    """Hide a file in an image using LSB steganography with compression.

    Writes a **v2** wire-format blob (see module docstring).  Existing images
    written in v1 format remain extractable — extraction is backward-compatible.

    When a password is supplied both the file metadata (filename + MIME type)
    and the file payload are encrypted independently with Fernet, so an
    adversary who reads the raw LSBs without the password learns *nothing*
    about the hidden file — not even its name.

    Args:
        image_path:  Path to the host image
        file_path:   Path to the file to hide
        output_path: Path where the output image will be saved
        password:    Optional encryption password

    Returns:
        Path to the output image

    Raises:
        ValueError: If the image doesn't have enough capacity, or if
                    metadata exceeds the maximum allowed length.
    """
    # Open the host image — we need the pixel list for writing back via putdata()
    host_img = Image.open(image_path).convert("RGB")

    # Guard: cap pixel allocation before we materialise it.
    total_pixels = host_img.width * host_img.height
    max_pixels = _MAX_PAYLOAD_BYTES * 8 // 3  # inverse of capacity formula
    if total_pixels > max_pixels:
        raise ValueError(
            "Host image dimensions exceed the maximum supported size."
        )

    host_pixels = list(host_img.getdata())  # required for putdata() write-back

    # ── 1. Read and compress the file ────────────────────────────────────────
    with open(file_path, "rb") as f:
        file_data = f.read()
    compressed_data = zlib.compress(file_data, level=9)

    # ── 2. Build metadata string ──────────────────────────────────────────────
    original_filename = os.path.basename(file_path)

    # Use an explicit curated map first — this is OS-independent and immune to
    # Windows registry corruption (e.g. .docx → spreadsheet MIME, .zip →
    # x-zip-compressed).  Fall back to mimetypes only for unknown extensions.
    ext = os.path.splitext(file_path)[1].lower()
    _MIME_MAP = {
        # Images
        ".png":  "image/png",
        ".jpg":  "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif":  "image/gif",
        ".bmp":  "image/bmp",
        ".webp": "image/webp",
        # Documents
        ".pdf":  "application/pdf",
        ".txt":  "text/plain",
        ".doc":  "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        # Archives / packages
        ".zip":  "application/zip",
        ".apk":  "application/vnd.android.package-archive",
        # Video
        ".mp4":  "video/mp4",
    }
    mime_type = _MIME_MAP.get(ext) or mimetypes.guess_type(file_path)[0] or "application/octet-stream"

    metadata_plain = f"{original_filename}|{mime_type}".encode("utf-8")

    # ── 3. Validate metadata length (v2 defence-in-depth) ────────────────────
    # This check applies to the plaintext.  After Fernet encryption the
    # ciphertext is larger; _encode_metadata_length() re-checks the final size.
    if len(metadata_plain) > _MAX_METADATA_PLAIN_LEN:
        raise ValueError(
            f"Filename or MIME type is too long "
            f"(metadata {len(metadata_plain)} B > {_MAX_METADATA_PLAIN_LEN} B limit)."
        )

    # ── 4. Encrypt or pass-through depending on password ─────────────────────
    password_flag = b"\x01" if password else b"\x00"
    salt = b""

    if password:
        salt = secrets.token_bytes(16)  # 16-byte random salt
        key = _derive_key_from_password(password, salt)
        fernet = Fernet(key)

        # Encrypt metadata and payload with the SAME key but as two independent
        # Fernet tokens.  Each token carries its own IV and HMAC so they are
        # cryptographically independent — knowing one does not help decrypt the
        # other without the key.
        metadata_field = fernet.encrypt(metadata_plain)   # ciphertext
        payload_field  = fernet.encrypt(compressed_data)  # ciphertext
    else:
        # No password: store plaintext metadata and unencrypted payload.
        metadata_field = metadata_plain
        payload_field  = compressed_data

    # ── 5. Encode lengths (v2: 4-byte metadata_length) ───────────────────────
    # _encode_metadata_length() performs an explicit cap check *before*
    # calling to_bytes(), converting any future OverflowError into a clear
    # ValueError 400 — closing the M-06 DoS vector entirely.
    metadata_length = _encode_metadata_length(len(metadata_field))  # 4 bytes
    data_length     = len(payload_field).to_bytes(_DATA_LEN_BYTES, "big")

    # ── 6. Assemble the v2 blob ───────────────────────────────────────────────
    # Layout: [magic(2)] [password_flag(1)] [salt?(16)] [metadata_len(4)] [meta] [data_len(4)] [payload]
    data_to_hide = (
        _V2_MAGIC + password_flag + salt + metadata_length + metadata_field + data_length + payload_field
    )

    # ── 7. Capacity check ────────────────────────────────────────────────────
    if len(data_to_hide) * 8 > total_pixels * 3:
        raise ValueError("Host image does not have enough capacity to store the data.")

    # ── 8. Embed via LSB ─────────────────────────────────────────────────────
    data_index = 0
    bit_index  = 0

    for i, pixel in enumerate(host_pixels):
        pixel = list(pixel)
        for channel in range(3):
            if data_index < len(data_to_hide):
                byte = data_to_hide[data_index]
                pixel[channel] = (pixel[channel] & ~1) | ((byte >> (7 - bit_index)) & 1)
                bit_index += 1
                if bit_index == 8:
                    bit_index  = 0
                    data_index += 1
        host_pixels[i] = tuple(pixel)

    # ── 9. Save ──────────────────────────────────────────────────────────────
    host_img.putdata(host_pixels)
    host_img.save(output_path, "PNG", optimize=False, compress_level=0)
    return output_path


def extract_file_from_image(
    image_path: str,
    password: str = None,
) -> tuple[bytes, str, str]:
    """Extract a hidden file from an image using a streaming LSB reader.

    Transparently handles both **v1** (legacy 2-byte metadata_length) and
    **v2** (current 4-byte metadata_length) wire formats.  Detection is based
    on the first two bytes: if they equal ``_V2_MAGIC`` (``0xFF 0x02``) the v2
    parser is used; otherwise the v1 parser is used.

    The extractor reads only as many pixels as required to reconstruct the
    payload — it never materialises the full pixel list or a full bit-list.
    Peak memory per request is proportional to the *extracted* payload size,
    not to the image size.

    Args:
        image_path: Path to the image containing hidden data
        password:   Password for decryption (if the file was encrypted)

    Returns:
        Tuple of (file_data, original_filename, mime_type)

    Raises:
        ValueError: If extraction fails, image is too small, or password is wrong
    """
    img = Image.open(image_path)

    # Compute the maximum bytes this image can carry — used to cap data_length
    # before we start reading, preventing crafted 4 GB data_length values.
    max_carriable = (img.width * img.height * 3) // 8

    gen = _iter_lsb_bytes(img)

    try:
        # ── Version sniff (2 bytes) ───────────────────────────────────────────
        # Read the first two bytes to determine the wire format version.
        # We cannot "un-read" from the generator, so we always consume exactly
        # 2 bytes here; the v1 path repurposes the second byte as part of the
        # password flag / salt.
        first_two = _read_exactly(gen, 2, "version header")

        if first_two == _V2_MAGIC:
            # ── V2 parser ────────────────────────────────────────────────────
            metadata_bytes, payload_bytes, has_password, salt = _parse_v2(
                gen, max_carriable, password
            )
        else:
            # ── V1 parser (backward-compatible) ──────────────────────────────
            # first_two[0] is the password_flag byte.
            # first_two[1] is the first byte of salt (if encrypted) or the
            # first byte of the 2-byte metadata_length (if plain).
            metadata_bytes, payload_bytes, has_password, salt = _parse_v1(
                gen, first_two, max_carriable, password
            )

        # ── Decrypt (if needed) ───────────────────────────────────────────────
        if has_password:
            if not password:
                raise ValueError("Password is required to extract this file.")
            try:
                key    = _derive_key_from_password(password, salt)
                fernet = Fernet(key)

                # Decrypt metadata first — if the password is wrong Fernet raises
                # InvalidToken here, before we even touch the (potentially large)
                # payload, giving a fast failure path.
                metadata_plain = fernet.decrypt(metadata_bytes)
                payload_bytes  = fernet.decrypt(payload_bytes)
            except Exception:
                raise ValueError("Incorrect password.")
        else:
            metadata_plain = metadata_bytes

        # ── Parse metadata ────────────────────────────────────────────────────
        try:
            metadata = metadata_plain.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(
                "Embedded metadata is not valid UTF-8. "
                "The image may not contain hidden data or may be corrupted."
            )

        if "|" not in metadata:
            raise ValueError(
                "Embedded metadata is malformed (missing separator). "
                "The image may not contain hidden data or may be corrupted."
            )
        original_filename, mime_type = metadata.split("|", 1)

        # ── Decompress ────────────────────────────────────────────────────────
        decompressed_data = zlib.decompress(payload_bytes)

        return decompressed_data, original_filename, mime_type

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to extract file: {exc}") from exc


# ── Private wire-format parsers ────────────────────────────────────────────────

def _parse_v2(
    gen,
    max_carriable: int,
    password: str | None,
) -> tuple[bytes, bytes, bool, bytes]:
    """Parse a v2 blob from *gen* (magic already consumed by caller).

    Returns:
        (metadata_bytes, payload_bytes, has_password, salt)
    """
    # ── Password flag (1 byte) ────────────────────────────────────────────────
    password_flag_byte = _read_exactly(gen, 1, "password flag")[0]
    has_password = password_flag_byte == 0x01

    if has_password and not password:
        raise ValueError("This file is password-protected. Please provide the password.")

    # ── Salt (16 bytes, only if encrypted) ────────────────────────────────────
    salt = b""
    if has_password:
        salt = _read_exactly(gen, 16, "encryption salt")

    # ── Metadata length (4 bytes, big-endian) ─────────────────────────────────
    metadata_length = int.from_bytes(
        _read_exactly(gen, _V2_META_LEN_BYTES, "metadata length"), "big"
    )

    max_meta_len = _MAX_METADATA_ENC_LEN if has_password else _MAX_METADATA_PLAIN_LEN
    if metadata_length == 0 or metadata_length > max_meta_len:
        raise ValueError(
            f"Embedded metadata length ({metadata_length} B) is outside the "
            f"valid range [1, {max_meta_len}]. "
            "The image may not contain hidden data or may be corrupted."
        )

    # ── Metadata field ────────────────────────────────────────────────────────
    metadata_bytes = _read_exactly(gen, metadata_length, "metadata")

    # ── Data length (4 bytes, big-endian) ─────────────────────────────────────
    data_length = int.from_bytes(
        _read_exactly(gen, _DATA_LEN_BYTES, "data length"), "big"
    )

    if data_length == 0 or data_length > min(max_carriable, _MAX_PAYLOAD_BYTES):
        raise ValueError(
            f"Embedded data length ({data_length} B) exceeds the image's "
            "carrying capacity. The image may not contain hidden data or "
            "may be corrupted."
        )

    # ── Payload ───────────────────────────────────────────────────────────────
    payload_bytes = _read_exactly(gen, data_length, "payload")

    return metadata_bytes, payload_bytes, has_password, salt


def _parse_v1(
    gen,
    first_two: bytes,
    max_carriable: int,
    password: str | None,
) -> tuple[bytes, bytes, bool, bytes]:
    """Parse a legacy v1 blob.

    *first_two* contains the two bytes already consumed by the version sniffer:
    ``first_two[0]`` is the v1 password_flag; ``first_two[1]`` is the first
    byte of the 15 remaining salt bytes (encrypted) or the first byte of the
    2-byte metadata_length (plain).

    Returns:
        (metadata_bytes, payload_bytes, has_password, salt)
    """
    password_flag_byte = first_two[0]
    has_password = password_flag_byte == 0x01

    if has_password and not password:
        raise ValueError("This file is password-protected. Please provide the password.")

    # ── Salt (16 bytes total; first byte already in first_two[1]) ─────────────
    salt = b""
    if has_password:
        # We consumed first_two[1] as the 2nd byte of the version-sniff, but
        # it is actually the 1st byte of the 16-byte salt.  Read the remaining
        # 15 bytes from the generator and prepend.
        remaining_salt = _read_exactly(gen, 15, "encryption salt")
        salt = bytes([first_two[1]]) + remaining_salt

    # ── Metadata length (2 bytes, big-endian — v1 legacy width) ───────────────
    if has_password:
        # Salt was fully consumed above; now read the two metadata-length bytes.
        meta_len_bytes = _read_exactly(gen, _V1_META_LEN_BYTES, "metadata length")
    else:
        # No salt: first_two[1] is the high byte of the 2-byte metadata_length.
        second_byte = _read_exactly(gen, 1, "metadata length")
        meta_len_bytes = bytes([first_two[1]]) + second_byte

    metadata_length = int.from_bytes(meta_len_bytes, "big")

    max_meta_len = _MAX_METADATA_ENC_LEN if has_password else _MAX_METADATA_PLAIN_LEN
    if metadata_length == 0 or metadata_length > max_meta_len:
        raise ValueError(
            f"Embedded metadata length ({metadata_length} B) is outside the "
            f"valid range [1, {max_meta_len}]. "
            "The image may not contain hidden data or may be corrupted."
        )

    # ── Metadata field ────────────────────────────────────────────────────────
    metadata_bytes = _read_exactly(gen, metadata_length, "metadata")

    # ── Data length (4 bytes, big-endian — same width in both versions) ────────
    data_length = int.from_bytes(
        _read_exactly(gen, _DATA_LEN_BYTES, "data length"), "big"
    )

    if data_length == 0 or data_length > min(max_carriable, _MAX_PAYLOAD_BYTES):
        raise ValueError(
            f"Embedded data length ({data_length} B) exceeds the image's "
            "carrying capacity. The image may not contain hidden data or "
            "may be corrupted."
        )

    # ── Payload ───────────────────────────────────────────────────────────────
    payload_bytes = _read_exactly(gen, data_length, "payload")

    return metadata_bytes, payload_bytes, has_password, salt
