"""Shared cryptographic utilities for InvisioVault.

All password-based key derivation is centralised here so that the exact same
audited implementation is used by every module (steganography, QR stego, etc.)
and there is only one place to update when security requirements change.

Key-derivation parameters
--------------------------
Algorithm  : PBKDF2-HMAC-SHA256
Iterations : 480 000  (OWASP recommended minimum for 2023+)
Key length : 32 bytes  → base64url-encoded → ready for Fernet()
Salt       : 16 bytes of cryptographically-random material, caller-supplied

Encryption primitive
---------------------
All symmetric encryption uses Fernet (AES-128-CBC + HMAC-SHA256).
Fernet is a well-audited, misuse-resistant symmetric cipher available through
the `cryptography` package that is already a project dependency.

Wire-format flag bytes (shared across steganography.py and qr_stego.py)
-------------------------------------------------------------------------
    0x00  Plain-text / unencrypted
    0x01  LEGACY — AES-256-CBC (no auth tag).  Rejected on read with a
          helpful message so users know to re-generate the artefact.
    0x02  Fernet-encrypted  (current; authenticated with HMAC-SHA256)

Only 0x00 and 0x02 are written by the current codebase.

Memory-hygiene limitations (CWE-244)
-------------------------------------
NIST SP 800-132 calls for key material to be erased from memory immediately
after use.  CPython cannot fully honour that:

* ``str`` and ``bytes`` are immutable — they cannot be overwritten in place,
  and the interpreter may hold additional copies (interning, slicing,
  Flask's form parsing of the password field, ``kdf.derive()``'s internal
  buffers, ``Fernet``'s internal signing/encryption key attributes).
* Garbage collection is not deterministic, and freed pages are not scrubbed.

What this module DOES provide is best-effort hygiene:

* :func:`zeroize` overwrites any mutable buffer (``bytearray``/``memoryview``)
  the caller managed to keep key material in.
* :func:`derive_fernet_key` zeroes its own mutable intermediate copy of the
  raw key before returning.
* Callers should ``del`` key/Fernet references as soon as they are done so
  the objects become collectable immediately rather than living to the end
  of the request.

The residual risk (immutable copies surviving until GC + possible swap-out)
is accepted and mitigated operationally: this is a stateless service, keys
are per-request and never persisted, and hosting should use encrypted swap
or swap disabled (the Render tier this deploys to does not swap containers
to disk).
"""

from __future__ import annotations

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ── Public constants ──────────────────────────────────────────────────────────

#: Number of PBKDF2 iterations — OWASP 2023+ recommendation.
PBKDF2_ITERATIONS: int = 480_000

#: Length of the PBKDF2 output in bytes (also the Fernet key material length).
PBKDF2_KEY_LENGTH: int = 32

#: Recommended salt length in bytes.
SALT_LENGTH: int = 16

# Flag bytes embedded in wire formats
FLAG_PLAIN: int = 0x00        # No encryption
FLAG_LEGACY_CBC: int = 0x01   # Deprecated AES-256-CBC (no auth) — reject on read
FLAG_FERNET: int = 0x02       # Current: Fernet (AES-128-CBC + HMAC-SHA256)


# ── Memory hygiene ────────────────────────────────────────────────────────────

def zeroize(buf) -> None:
    """Overwrite a mutable buffer with zeros, in place (best-effort, CWE-244).

    Accepts ``bytearray`` or writable ``memoryview``.  Immutable types
    (``bytes``/``str``) cannot be zeroed in CPython — see the module
    docstring for the documented limitation; for those, the best available
    action is for the caller to ``del`` the reference promptly.

    Safe to call multiple times and on empty buffers.
    """
    if isinstance(buf, memoryview):
        if not buf.readonly:
            buf[:] = bytes(len(buf))
    elif isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


# ── Key derivation ────────────────────────────────────────────────────────────

def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a user password and a random salt.

    The returned value is a 44-byte, base64url-encoded string (as ``bytes``)
    that can be passed directly to ``Fernet(key)``.

    Memory hygiene: the mutable intermediate copy of the raw 32-byte key is
    zeroed before this function returns.  The returned base64 key and the
    KDF's internal output are immutable ``bytes`` and cannot be scrubbed —
    callers should ``del`` the returned key (and any ``Fernet`` built from
    it) as soon as encryption/decryption is complete.  See the module
    docstring for the full limitation statement.

    Args:
        password: User-supplied plaintext password.
        salt:     ``SALT_LENGTH`` bytes of cryptographically-random material.
                  Must be generated with ``secrets.token_bytes(SALT_LENGTH)``
                  or ``os.urandom(SALT_LENGTH)`` by the caller.

    Returns:
        44-byte base64url-encoded Fernet key (``bytes``).

    Raises:
        ValueError: If *salt* is shorter than ``SALT_LENGTH`` bytes.
    """
    if len(salt) < SALT_LENGTH:
        raise ValueError(
            f"Salt must be at least {SALT_LENGTH} bytes; got {len(salt)}."
        )

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    # Copy the derived key into a mutable buffer so it can be zeroed.
    raw_key = bytearray(kdf.derive(password.encode("utf-8")))
    try:
        # Fernet requires a URL-safe base64-encoded 32-byte key.
        return base64.urlsafe_b64encode(bytes(raw_key))
    finally:
        zeroize(raw_key)
