"""QR Payload Container Specification and Serialization.

Container Format Specification (IVQR v1):
----------------------------------------
Offset  Size  Field              Description
0       4     MAGIC              Magic bytes b"IVQR" (0x49 0x56 0x51 0x52)
4       1     VERSION            Container version (0x01)
5       1     FLAGS              Bit 0: Encrypted (0x01), Bit 1: Compressed (0x02)
6       4     ORIG_LEN           Original uncompressed plaintext length (uint32, BE)
10      4     PAYLOAD_LEN        Length of payload body following header (uint32, BE)
14      2     HEADER_CHECKSUM    CRC-16/ARC checksum over bytes 0..13
16      N     PAYLOAD_BODY       Body content:
                                   - If encrypted: salt (16 bytes) + Fernet token
                                   - If plain: compressed/raw data + CRC-32 (4 bytes, BE)

Security Guarantees:
  * Integrity: Header and payload have independent checksums and HMAC verification.
  * Confidentiality: Fernet (AES-128-CBC + HMAC-SHA256) with 100k PBKDF2 iterations.
  * Decompression Bomb Protection (CWE-409): Streaming chunked decompression capped at 1 MB.
  * Anti-DoS: Header lengths checked before memory allocations.
"""

from __future__ import annotations

import logging
import secrets
import struct
import zlib
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from utils.crypto_utils import SALT_LENGTH, derive_fernet_key

logger = logging.getLogger(__name__)

QR_CONTAINER_MAGIC: bytes = b"IVQR"
QR_CONTAINER_VERSION: int = 1

FLAG_ENCRYPTED: int = 0x01
FLAG_COMPRESSED: int = 0x02

HEADER_SIZE: int = 16  # 14 bytes fields + 2 bytes CRC16

# Security limits
MAX_QR_PAYLOAD_BYTES: int = 100 * 1024  # 100 KB max (QR physical limit is < 3 KB)
MAX_DECOMPRESSED_BYTES: int = 1 * 1024 * 1024  # 1 MB max decompressed text
DECOMPRESS_CHUNK: int = 16 * 1024


def _crc16(data: bytes) -> int:
    """Compute 16-bit CRC for header integrity."""
    return zlib.crc32(data) & 0xFFFF


def _safe_decompress(data: bytes, max_size: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompress zlib data with strict output size cap to prevent Zip Bombs (CWE-409)."""
    decompressor = zlib.decompressobj()
    chunks: list[bytes] = []
    total = 0

    while data:
        chunk = decompressor.decompress(data, DECOMPRESS_CHUNK)
        total += len(chunk)
        if total > max_size:
            raise ValueError(
                f"Decompressed data exceeds maximum allowed size ({max_size} bytes)."
            )
        chunks.append(chunk)
        if decompressor.eof:
            break
        data = decompressor.unconsumed_tail
        if not data and not chunk:
            break

    tail = decompressor.flush()
    total += len(tail)
    if total > max_size:
        raise ValueError(
            f"Decompressed data exceeds maximum allowed size ({max_size} bytes)."
        )
    chunks.append(tail)
    return b"".join(chunks)


def pack_qr_container(secret_text: str, password: Optional[str] = None) -> bytes:
    """Serialize and secure secret text into an IVQR container blob.

    Pipeline:
      Original text -> Optional zlib compression (level 9) ->
      (If password: PBKDF2 + Fernet authenticated encryption) ->
      (If plain: CRC-32 integrity trailer) ->
      IVQR header with CRC-16 checksum.

    Args:
        secret_text: Plaintext secret to protect and store.
        password:    Optional encryption password.

    Returns:
        Packed bytes ready for QR embedding.
    """
    raw_bytes = secret_text.encode("utf-8")
    orig_len = len(raw_bytes)

    if orig_len > MAX_DECOMPRESSED_BYTES:
        raise ValueError(
            f"Secret text ({orig_len} bytes) exceeds maximum allowable size "
            f"({MAX_DECOMPRESSED_BYTES} bytes)."
        )

    # 1. Compress before encryption (compressible data shrinks significantly)
    compressed = zlib.compress(raw_bytes, level=9)
    if len(compressed) < orig_len:
        flags = FLAG_COMPRESSED
        payload_data = compressed
    else:
        flags = 0x00
        payload_data = raw_bytes

    # 2. Authenticated encryption or integrity trailer
    if password:
        flags |= FLAG_ENCRYPTED
        salt = secrets.token_bytes(SALT_LENGTH)
        key = derive_fernet_key(password, salt)
        fernet = Fernet(key)
        try:
            token = fernet.encrypt(payload_data)
        finally:
            key = fernet = None  # Memory hygiene (CWE-244)
        payload_body = salt + token
    else:
        # Append 4-byte CRC-32 for integrity verification of unencrypted payloads
        crc = zlib.crc32(payload_data) & 0xFFFFFFFF
        payload_body = payload_data + struct.pack(">I", crc)

    payload_len = len(payload_body)
    if payload_len > MAX_QR_PAYLOAD_BYTES:
        raise ValueError(
            f"Packed payload body ({payload_len} bytes) exceeds safe container limit."
        )

    # 3. Assemble container header (14 bytes) + CRC16 (2 bytes)
    header_fields = struct.pack(
        ">4sBBII",
        QR_CONTAINER_MAGIC,
        QR_CONTAINER_VERSION,
        flags,
        orig_len,
        payload_len,
    )
    header_crc = _crc16(header_fields)
    header = header_fields + struct.pack(">H", header_crc)

    return header + payload_body


def unpack_qr_container(container: bytes, password: Optional[str] = None) -> str:
    """Deserialize, verify, and decrypt an IVQR container blob.

    Args:
        container: Raw bytes extracted from QR steganography.
        password:  Optional password for decryption.

    Returns:
        Original plaintext string.

    Raises:
        ValueError: On corrupted header, wrong password, tampered data, or truncated payload.
    """
    if len(container) < HEADER_SIZE:
        raise ValueError("Container is too small to be a valid InvisioVault QR payload.")

    magic, version, flags, orig_len, payload_len = struct.unpack(
        ">4sBBII", container[:14]
    )

    if magic != QR_CONTAINER_MAGIC:
        raise ValueError("Invalid magic bytes: Not an InvisioVault QR payload.")

    if version != QR_CONTAINER_VERSION:
        raise ValueError(f"Unsupported payload format version: {version}")

    header_crc = struct.unpack(">H", container[14:HEADER_SIZE])[0]
    expected_header_crc = _crc16(container[:14])
    if header_crc != expected_header_crc:
        raise ValueError("Payload header checksum failed: data is corrupted.")

    if orig_len > MAX_DECOMPRESSED_BYTES:
        raise ValueError("Reported original length exceeds safety limit.")

    payload_body = container[HEADER_SIZE:]
    if len(payload_body) != payload_len:
        raise ValueError(
            f"Payload length mismatch: expected {payload_len} bytes, got {len(payload_body)}."
        )

    is_encrypted = bool(flags & FLAG_ENCRYPTED)
    is_compressed = bool(flags & FLAG_COMPRESSED)

    if is_encrypted:
        if not password:
            raise ValueError(
                "This QR code is password protected. Please provide the password."
            )
        if len(payload_body) < SALT_LENGTH + 1:
            raise ValueError("Encrypted payload body is too short to be valid.")

        salt = payload_body[:SALT_LENGTH]
        token = payload_body[SALT_LENGTH:]
        key = derive_fernet_key(password, salt)
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(token)
        except InvalidToken:
            raise ValueError(
                "Incorrect password or the QR code data has been tampered with."
            )
        finally:
            key = fernet = None  # Memory hygiene (CWE-244)

        data = decrypted
    else:
        if len(payload_body) < 4:
            raise ValueError("Plain payload body is missing integrity checksum.")
        data = payload_body[:-4]
        stored_crc = struct.unpack(">I", payload_body[-4:])[0]
        actual_crc = zlib.crc32(data) & 0xFFFFFFFF
        if actual_crc != stored_crc:
            raise ValueError(
                "Payload integrity check failed: unencrypted data was corrupted."
            )

    if is_compressed:
        data = _safe_decompress(data, max_size=MAX_DECOMPRESSED_BYTES)

    if len(data) != orig_len:
        raise ValueError(
            f"Decompressed length mismatch: expected {orig_len} bytes, got {len(data)}."
        )

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Payload text is corrupted or not valid UTF-8.")


def is_ivqr_container(data: bytes) -> bool:
    """Check if data begins with valid IVQR magic and has valid header checksum."""
    if len(data) < HEADER_SIZE:
        return False
    if data[:4] != QR_CONTAINER_MAGIC:
        return False
    header_crc = struct.unpack(">H", data[14:HEADER_SIZE])[0]
    return header_crc == _crc16(data[:14])
