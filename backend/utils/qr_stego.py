"""QR Code steganography utilities for generating customised QR codes with
hidden data.

Encryption scheme (M-02 fix)
-----------------------------
Previously the optional password path used raw AES-256-CBC, which provides
*confidentiality* but **no authenticity**.  An observer who can see the
ciphertext can:

  * Execute a padding-oracle attack if error responses differ.
  * Perform targeted bit-flip attacks (CBC malleability) to corrupt or
    selectively modify plaintext bytes in a predictable way.

The fix replaces that path with **Fernet** (AES-128-CBC + HMAC-SHA256 under
the hood), which is the same primitive already used by steganography.py.
Fernet is a high-level, misuse-resistant AEAD construction: the ciphertext
is rejected in constant time if the HMAC tag does not verify, eliminating
both the padding-oracle and the bit-flip vectors.

Wire format (QR fragment payload)
----------------------------------
The base64-encoded IVDATA fragment payload is always:

    Without password:
        [0x00] + UTF-8 secret bytes

    With password (current, v2):
        [0x02] + salt(16 bytes) + fernet_token(variable)

    Legacy / rejected (v1 — old AES-CBC):
        [0x01] + ...  →  ValueError on read with actionable message

Flag bytes are defined in utils.crypto_utils and documented there.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
import tempfile
from typing import Optional, Tuple

import numpy as np
import segno
import zxingcpp
from PIL import Image

from cryptography.fernet import Fernet, InvalidToken

from utils.crypto_utils import (
    FLAG_FERNET,
    FLAG_LEGACY_CBC,
    FLAG_PLAIN,
    SALT_LENGTH,
    derive_fernet_key,
)

logger = logging.getLogger(__name__)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _encrypt_secret(secret_text: str, password: str) -> bytes:
    """Encrypt *secret_text* with *password* using Fernet.

    Wire format of returned bytes:
        [0x02 (1)] + [salt (16)] + [fernet_token (variable)]

    Args:
        secret_text: Plaintext secret to encrypt.
        password:    User-supplied password.

    Returns:
        Raw payload bytes (not base64-encoded).
    """
    salt = secrets.token_bytes(SALT_LENGTH)
    key = derive_fernet_key(password, salt)
    fernet = Fernet(key)
    token = fernet.encrypt(secret_text.encode("utf-8"))
    return bytes([FLAG_FERNET]) + salt + token


def _decrypt_secret(payload_body: bytes, password: str) -> str:
    """Decrypt a Fernet-encrypted payload body (after the flag byte).

    Args:
        payload_body: Raw bytes after the 0x02 flag byte.
                      Expected: salt(16) + fernet_token.
        password:     User-supplied password.

    Returns:
        Decrypted plaintext string.

    Raises:
        ValueError: On tampered ciphertext, wrong password, or malformed data.
    """
    if len(payload_body) < SALT_LENGTH + 1:
        raise ValueError(
            "Encrypted payload is too short to be valid "
            f"(expected > {SALT_LENGTH} bytes, got {len(payload_body)})."
        )

    salt = payload_body[:SALT_LENGTH]
    token = payload_body[SALT_LENGTH:]

    key = derive_fernet_key(password, salt)
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(token)
    except InvalidToken:
        # InvalidToken is raised for both wrong password AND tampered ciphertext.
        # We intentionally surface a single, non-differentiating error to
        # prevent oracle-style probing of which condition triggered.
        raise ValueError("Incorrect password or the QR code data has been tampered with.")

    return plaintext.decode("utf-8")


def _encode_payload(secret_text: str, password: Optional[str]) -> str:
    """Assemble and base64-encode the IVDATA fragment payload.

    Args:
        secret_text: The plaintext secret to embed.
        password:    Optional encryption password.

    Returns:
        ASCII base64 string ready for embedding into the QR fragment.
    """
    if password:
        raw_payload = _encrypt_secret(secret_text, password)
    else:
        raw_payload = bytes([FLAG_PLAIN]) + secret_text.encode("utf-8")

    return base64.b64encode(raw_payload).decode("ascii")


def _decode_payload(secret_encoded: str, password: Optional[str]) -> str:
    """Base64-decode and decrypt (if needed) an IVDATA fragment payload.

    Args:
        secret_encoded: Base64-encoded payload string from the QR fragment.
        password:       Optional decryption password.

    Returns:
        Plaintext secret string.

    Raises:
        ValueError: On any decoding, decryption, or format error.
    """
    try:
        raw_payload = base64.b64decode(secret_encoded)
    except Exception:
        raise ValueError("Hidden data could not be decoded — the QR content may be corrupted.")

    if len(raw_payload) < 1:
        raise ValueError("Invalid payload: missing format flag byte.")

    flag = raw_payload[0]
    body = raw_payload[1:]

    if flag == FLAG_PLAIN:
        if password:
            logger.warning(
                "A password was provided but the payload is not encrypted; "
                "the password will be ignored."
            )
        return body.decode("utf-8")

    if flag == FLAG_LEGACY_CBC:
        # M-02 mitigation: refuse to process old unauthenticated payloads.
        # Decrypting a CBC ciphertext without verifying its integrity first
        # would expose us to padding-oracle and malleability attacks.
        raise ValueError(
            "This QR code was generated with an older, insecure encryption "
            "scheme (AES-CBC without authentication). "
            "Please ask the creator to regenerate it with InvisioVault."
        )

    if flag == FLAG_FERNET:
        if not password:
            raise ValueError("This QR code is password protected. Please provide the password.")
        return _decrypt_secret(body, password)

    raise ValueError(
        f"Unknown payload format flag 0x{flag:02X}. "
        "The QR code may have been generated by a newer version of InvisioVault."
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_qr_with_stego(
    public_data: str,
    secret_text: str,
    output_path: str,
    password: Optional[str] = None,
    fg_color: str = "#000000",
    bg_color: str = "#FFFFFF",
    scale: int = 20,
    logo_path: Optional[str] = None,
) -> str:
    """Generate a QR code with an authenticated-encrypted hidden secret.

    The QR code data is:
        ``<public_data>#IVDATA:<base64_payload>``

    Standard QR scanners open the URL and silently ignore the fragment.
    InvisioVault's extractor parses the fragment to recover the secret.

    This approach is robust against camera capture and recompression (unlike
    LSB pixel steganography) because the secret lives inside the QR data
    stream itself, not in the image pixels.

    Encryption (when *password* is supplied) uses Fernet, which provides
    authenticated encryption (AES-128-CBC + HMAC-SHA256).  An attacker who
    intercepts or modifies the ciphertext will trigger an HMAC failure on
    decryption — the tampered data is rejected before any plaintext is
    produced, preventing both padding-oracle and ciphertext-malleability
    attacks.

    Args:
        public_data: Visible QR data (URL, vCard, plain text, etc.).
        secret_text: Hidden message to embed.
        output_path: Filesystem path where the PNG will be written.
        password:    Optional password.  ``None`` → plaintext embedding
                     (flag 0x00).  Non-empty string → Fernet encryption
                     (flag 0x02).
        fg_color:    QR module colour in CSS hex notation (default: black).
        bg_color:    QR background colour in CSS hex notation (default: white).
        scale:       QR pixel-scale multiplier (default: 20).
        logo_path:   Optional path to a logo PNG to embed in the centre.

    Returns:
        *output_path* (unchanged) for convenience.

    Raises:
        ValueError: If QR generation fails for any reason.
    """
    try:
        secret_encoded = _encode_payload(secret_text, password)
        logger.info("Secret encoded to %d base64 characters.", len(secret_encoded))

        combined_qr_data = f"{public_data}#IVDATA:{secret_encoded}"
        logger.info("Combined QR data length: %d characters.", len(combined_qr_data))

        qr = segno.make(combined_qr_data, error="h")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            temp_qr_path = tmp.name

        try:
            qr.save(temp_qr_path, scale=scale, dark=fg_color, light=bg_color, border=2)
            logger.info("QR code saved to temp file: %s", temp_qr_path)

            if logo_path:
                logger.info("Embedding logo from: %s", logo_path)
                _embed_logo_in_qr(temp_qr_path, logo_path)

            # Convert to plain RGB PNG (no alpha, no palette) for maximum
            # compatibility with scanners and subsequent LSB operations.
            Image.open(temp_qr_path).convert("RGB").save(
                output_path, "PNG", optimize=False, compress_level=0
            )
            logger.info("Final QR code saved to: %s", output_path)
        finally:
            if os.path.exists(temp_qr_path):
                os.remove(temp_qr_path)

        return output_path

    except Exception as exc:
        logger.error("Failed to generate QR code: %s", exc, exc_info=True)
        raise ValueError(f"Failed to generate QR code: {exc}") from exc


def extract_from_qr_stego(
    qr_path: str,
    password: Optional[str] = None,
) -> Tuple[str, str]:
    """Extract the visible QR data and the hidden secret from a QR code image.

    The QR data is expected to contain an ``#IVDATA:<base64>`` fragment
    produced by :func:`generate_qr_with_stego`.  QR codes without that
    fragment are treated as ordinary QR codes — ``secret_text`` is returned
    as an empty string.

    If the payload was encrypted with a password the ciphertext is verified
    (HMAC) before any decryption occurs, so a wrong or missing password is
    detected immediately without leaking timing information about the padding.

    Args:
        qr_path:  Path to the QR code image.
        password: Decryption password (required if the QR was sealed with one).

    Returns:
        ``(public_qr_data, secret_text)``

    Raises:
        ValueError: If no QR code is found, decryption fails, or data is
                    malformed/tampered.
    """
    try:
        logger.info("Extracting from QR code: %s", qr_path)
        img_array = np.array(Image.open(qr_path).convert("RGB"))
        decoded_objects = zxingcpp.read_barcodes(img_array)

        if not decoded_objects:
            raise ValueError("No QR code found in the image.")

        qr_data = decoded_objects[0].text
        logger.info("Full QR data (first 100 chars): %s", qr_data[:100])

        if "#IVDATA:" not in qr_data:
            logger.info("No IVDATA fragment found — treating as a regular QR code.")
            return qr_data, ""

        parts = qr_data.split("#IVDATA:", maxsplit=1)
        public_data = parts[0]
        secret_encoded = parts[1] if len(parts) > 1 else ""

        if not secret_encoded:
            return public_data, ""

        secret_text = _decode_payload(secret_encoded, password)
        logger.info(
            "Extraction complete. Public: %d chars, Secret: %d chars.",
            len(public_data),
            len(secret_text),
        )
        return public_data, secret_text

    except ValueError:
        raise
    except Exception as exc:
        logger.error("Failed to extract data from QR code: %s", exc, exc_info=True)
        raise ValueError(f"Failed to extract data from QR code: {exc}") from exc


def calculate_qr_capacity(public_data: str, scale: int = 10) -> int:
    """Estimate the LSB steganography capacity of a QR code in bytes.

    This is an informational helper for UI feedback; it does not affect the
    security of the hidden payload (which lives in the QR data stream).

    Args:
        public_data: The public QR data (determines QR version and size).
        scale:       QR pixel-scale multiplier.

    Returns:
        Estimated capacity in bytes; 0 if the QR cannot be generated.
    """
    try:
        qr = segno.make(public_data, error="h")

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            temp_path = tmp.name

        try:
            qr.save(temp_path, scale=scale, border=2)
            img = Image.open(temp_path).convert("RGB")
            # 3 bits per pixel (1 per RGB channel) divided by 8 → bytes.
            # Subtract a small header overhead estimate.
            capacity_bytes = (img.width * img.height * 3) // 8 - 100
            return max(0, capacity_bytes)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception:
        return 90_000  # Conservative fallback for typical QR dimensions


def decode_qr_only(qr_path: str) -> str:
    """Decode only the visible QR code data, without secret extraction.

    Args:
        qr_path: Path to the QR code image.

    Returns:
        The raw QR data string as decoded by the zxing-cpp library.

    Raises:
        ValueError: If no QR code is found in the image.
    """
    try:
        img_array = np.array(Image.open(qr_path).convert("RGB"))
        decoded_objects = zxingcpp.read_barcodes(img_array)

        if not decoded_objects:
            raise ValueError("No QR code found in the image.")

        return decoded_objects[0].text

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to decode QR code: {exc}") from exc


# ── Private helpers ───────────────────────────────────────────────────────────

def _embed_logo_in_qr(qr_path: str, logo_path: str) -> None:
    """Embed a logo image in the centre of a QR code (in-place).

    The logo is scaled to at most 20 % of the QR's shorter dimension to
    preserve scannability at the 'H' error-correction level.

    Args:
        qr_path:   Path to the QR code PNG (overwritten in place).
        logo_path: Path to the logo image (any PIL-supported format).
    """
    qr_img = Image.open(qr_path).convert("RGBA")
    logo_img = Image.open(logo_path).convert("RGBA")

    qr_w, qr_h = qr_img.size
    max_logo = int(min(qr_w, qr_h) * 0.20)
    logo_img.thumbnail((max_logo, max_logo), Image.Resampling.LANCZOS)

    logo_w, logo_h = logo_img.size
    pos = ((qr_w - logo_w) // 2, (qr_h - logo_h) // 2)

    # White backing card ensures contrast regardless of QR background colour.
    backing = Image.new("RGBA", logo_img.size, "WHITE")
    backing.paste(logo_img, (0, 0), logo_img)

    qr_img.paste(backing, pos, backing)
    qr_img.convert("RGB").save(qr_path, "PNG")
