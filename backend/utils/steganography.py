"""Steganography utilities for hiding and extracting files in images."""
from PIL import Image
import zlib
import mimetypes
import os
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import itertools


# ── Safety caps ───────────────────────────────────────────────────────────────
# Maximum filename + MIME string we will ever trust from an embedded header.
# No legitimate value can exceed 512 bytes; anything larger signals corruption
# or a crafted payload designed to exhaust memory before we reach data_length.
_MAX_METADATA_LEN: int = 512

# Absolute upper bound on how many raw (compressed / encrypted) payload bytes
# we will ever materialise from a single image.  10 MB covers the maximum
# upload limit enforced in validators.py; the factor of 10 gives a generous
# headroom for pre-compression inflation while still bounding the allocation.
_MAX_PAYLOAD_BYTES: int = 10 * 1024 * 1024 * 10  # 100 MB hard cap


def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a password using PBKDF2 with salt.

    Args:
        password: User password
        salt: 16-byte salt for key derivation

    Returns:
        32-byte Fernet key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # OWASP recommended minimum for 2023+
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)


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


# ── Public API ─────────────────────────────────────────────────────────────────

def hide_file_in_image(
    image_path: str,
    file_path: str,
    output_path: str,
    password: str = None,
) -> str:
    """Hide a file in an image using LSB steganography with compression.

    Args:
        image_path: Path to the host image
        file_path:  Path to the file to hide
        output_path: Path where the output image will be saved
        password:   Optional encryption password

    Returns:
        Path to the output image

    Raises:
        ValueError: If the image doesn't have enough capacity
    """
    # Open the host image — we need the pixel list for writing back via putdata()
    host_img = Image.open(image_path).convert("RGB")

    # Guard: cap pixel allocation before we materialise it.
    # For a 10 MP image this is ~10 M tuples × ~88 B each ≈ 880 MB — manageable
    # for the hide path but we still enforce a reasonable limit.
    total_pixels = host_img.width * host_img.height
    max_pixels = _MAX_PAYLOAD_BYTES * 8 // 3  # inverse of capacity formula
    if total_pixels > max_pixels:
        raise ValueError(
            "Host image dimensions exceed the maximum supported size."
        )

    host_pixels = list(host_img.getdata())  # required for putdata() write-back

    # Read and compress the file
    with open(file_path, "rb") as f:
        file_data = f.read()
    compressed_data = zlib.compress(file_data, level=9)

    # Generate salt and encrypt if password is provided
    salt = b""
    if password:
        salt = secrets.token_bytes(16)  # 16-byte random salt
        key = _derive_key_from_password(password, salt)
        fernet = Fernet(key)
        compressed_data = fernet.encrypt(compressed_data)

    # Prepare metadata
    original_filename = os.path.basename(file_path)

    # Better MIME type detection
    mime_type = mimetypes.guess_type(file_path)[0]
    if not mime_type:
        ext = os.path.splitext(file_path)[1].lower()
        mime_map = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".bmp": "image/bmp",
            ".webp": "image/webp",
            ".pdf": "application/pdf",
            ".txt": "text/plain",
            ".zip": "application/zip",
            ".mp4": "video/mp4",
        }
        mime_type = mime_map.get(ext, "application/octet-stream")

    # Add password flag to metadata (1 byte: 0x00 for no password, 0x01 for password)
    password_flag = b"\x01" if password else b"\x00"
    metadata = f"{original_filename}|{mime_type}".encode("utf-8")

    # Sanity-check metadata length before embedding
    if len(metadata) > _MAX_METADATA_LEN:
        raise ValueError(
            f"Filename or MIME type is too long "
            f"(metadata {len(metadata)} B > {_MAX_METADATA_LEN} B limit)."
        )

    metadata_length = len(metadata).to_bytes(2, "big")

    # Store the length of compressed data (4 bytes)
    data_length = len(compressed_data).to_bytes(4, "big")

    # Structure: [password_flag(1)] [salt(16 if encrypted)] [metadata_length(2)]
    #            [metadata] [data_length(4)] [compressed_data]
    data_to_hide = (
        password_flag + salt + metadata_length + metadata + data_length + compressed_data
    )

    # Check image capacity
    if len(data_to_hide) * 8 > total_pixels * 3:
        raise ValueError("Host image does not have enough capacity to store the data.")

    # Embed data into the image using LSB
    data_index = 0
    bit_index = 0

    for i, pixel in enumerate(host_pixels):
        pixel = list(pixel)
        for channel in range(3):
            if data_index < len(data_to_hide):
                byte = data_to_hide[data_index]
                pixel[channel] = (pixel[channel] & ~1) | ((byte >> (7 - bit_index)) & 1)
                bit_index += 1
                if bit_index == 8:
                    bit_index = 0
                    data_index += 1
        host_pixels[i] = tuple(pixel)

    # Save the modified image
    host_img.putdata(host_pixels)
    host_img.save(output_path, "PNG", optimize=False, compress_level=0)
    return output_path


def extract_file_from_image(
    image_path: str,
    password: str = None,
) -> tuple[bytes, str, str]:
    """Extract a hidden file from an image using a streaming LSB reader.

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
        # ── 1. Password flag (1 byte) ────────────────────────────────────────
        password_flag_byte = _read_exactly(gen, 1, "password flag")[0]
        has_password = password_flag_byte == 0x01

        if has_password and not password:
            raise ValueError("This file is password-protected. Please provide the password.")

        # ── 2. Salt (16 bytes, only if encrypted) ───────────────────────────
        salt = b""
        if has_password:
            salt = _read_exactly(gen, 16, "encryption salt")

        # ── 3. Metadata length (2 bytes, big-endian) ────────────────────────
        metadata_length = int.from_bytes(_read_exactly(gen, 2, "metadata length"), "big")

        # Guard against a crafted metadata_length that would exhaust memory
        # before we even reach the payload.
        if metadata_length == 0 or metadata_length > _MAX_METADATA_LEN:
            raise ValueError(
                f"Embedded metadata length ({metadata_length} B) is outside the "
                f"valid range [1, {_MAX_METADATA_LEN}]. "
                "The image may not contain hidden data or may be corrupted."
            )

        # ── 4. Metadata bytes ────────────────────────────────────────────────
        try:
            metadata = _read_exactly(gen, metadata_length, "metadata").decode("utf-8")
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

        # ── 5. Data length (4 bytes, big-endian) ─────────────────────────────
        data_length = int.from_bytes(_read_exactly(gen, 4, "data length"), "big")

        # Guard: clamp data_length against both the theoretical image capacity
        # and our hard cap, preventing allocation of multi-gigabyte buffers.
        if data_length == 0 or data_length > min(max_carriable, _MAX_PAYLOAD_BYTES):
            raise ValueError(
                f"Embedded data length ({data_length} B) exceeds the image's "
                "carrying capacity. The image may not contain hidden data or "
                "may be corrupted."
            )

        # ── 6. Payload (exactly data_length bytes) ───────────────────────────
        # islice stops the generator after data_length bytes — pixels beyond
        # the payload are never decoded, keeping memory proportional to output.
        compressed_data = _read_exactly(gen, data_length, "payload")

        # ── 7. Decrypt (if needed) ───────────────────────────────────────────
        if has_password:
            if not password:
                raise ValueError("Password is required to extract this file.")
            try:
                key = _derive_key_from_password(password, salt)
                fernet = Fernet(key)
                compressed_data = fernet.decrypt(compressed_data)
            except Exception:
                raise ValueError("Incorrect password.")

        # ── 8. Decompress ────────────────────────────────────────────────────
        decompressed_data = zlib.decompress(compressed_data)

        return decompressed_data, original_filename, mime_type

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to extract file: {exc}") from exc
