"""Polyglot file utilities for hiding files within other files.

A polyglot file simultaneously satisfies two file format parsers:
  • The carrier-format parser reads from the BEGINNING of the file, so it
    sees only the original carrier bytes and ignores the appended ZIP data.
  • ZIP readers scan from the END of the file (EOCD record), so they see a
    valid ZIP regardless of what precedes it.

The only post-concatenation work required is adjusting every absolute offset
stored inside the ZIP structures (central directory, ZIP64 EOCD, etc.) by
adding the carrier size — that is what _fix_zip_offsets() does.
"""
from __future__ import annotations

import os
import struct
import tempfile
import zipfile
from typing import Tuple

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False

# ---------------------------------------------------------------------------
# Low-level ZIP / ZIP64 constants (PKWARE APPNOTE 6.3.10)
# ---------------------------------------------------------------------------
_SIG_LFH     = b"PK\x03\x04"   # Local File Header
_SIG_CDFH    = b"PK\x01\x02"   # Central Directory File Header
_SIG_EOCD    = b"PK\x05\x06"   # End of Central Directory
_SIG_Z64_LOC = b"PK\x06\x07"   # ZIP64 EOCD Locator
_SIG_Z64_EOC = b"PK\x06\x06"   # ZIP64 End of Central Directory

_U32_MAX = 0xFFFF_FFFF          # ZIP64 sentinel for 32-bit fields
_U16_MAX = 0xFFFF               # ZIP64 sentinel for 16-bit fields

# EOCD field offsets (relative to start of EOCD record)
_EOCD_OFF_CD_OFFSET = 16        # uint32 LE: offset of CD start

# ZIP64 EOCD Locator field offsets
_Z64_LOC_OFF_Z64_EOC_OFFSET = 8   # uint64 LE: offset of ZIP64 EOCD record

# ZIP64 EOCD field offsets
_Z64_EOC_OFF_CD_OFFSET = 48       # uint64 LE: offset of CD start

# Central Directory File Header field offsets
_CDFH_OFF_COMP_SIZE   = 20        # uint32 LE: uncompressed size
_CDFH_OFF_UNCOMP_SIZE = 24        # uint32 LE: compressed size   (spec order: uncomp first, comp second at +24)
_CDFH_OFF_NAME_LEN    = 28        # uint16 LE
_CDFH_OFF_EXTRA_LEN   = 30        # uint16 LE
_CDFH_OFF_COMMENT_LEN = 32        # uint16 LE
_CDFH_OFF_LHO         = 42        # uint32 LE: relative offset of local header
_CDFH_SIZE            = 46        # fixed-size header (excludes variable-length fields)

# ZIP64 Extra Field tag
_Z64_EXTRA_TAG = 0x0001


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_polyglot(
    carrier_path: str,
    file_to_hide_path: str,
    output_path: str,
    password: str | None = None,
) -> str:
    """Create a polyglot file that is simultaneously valid as the carrier
    format *and* as a self-contained ZIP archive.

    The output file is written atomically: if anything goes wrong after
    the output file is created (including the offset-patching step) the
    partial output file is deleted and the exception is re-raised.

    Args:
        carrier_path:      Path to the carrier file (any format).
        file_to_hide_path: Path to the file to hide inside the polyglot.
        output_path:       Destination path for the polyglot file.
        password:          Optional AES password (requires pyzipper).

    Returns:
        ``output_path`` on success.

    Raises:
        FileNotFoundError: If carrier or file-to-hide does not exist.
        ValueError:        If the ZIP structure cannot be patched.
        OSError:           On filesystem errors.
    """
    original_filename = os.path.basename(file_to_hide_path)

    # We build the ZIP into a temp file first so that failures during ZIP
    # creation can never leave a half-written output file.
    tmp_zip_fd, tmp_zip_path = tempfile.mkstemp(suffix=".zip")
    os.close(tmp_zip_fd)

    output_created = False
    try:
        # ------------------------------------------------------------------ #
        # 1. Create the ZIP archive (hidden payload)                          #
        # ------------------------------------------------------------------ #
        if password and HAS_PYZIPPER:
            with pyzipper.AESZipFile(
                tmp_zip_path, "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as zf:
                zf.setpassword(password.encode())
                zf.write(file_to_hide_path, original_filename)
        else:
            with zipfile.ZipFile(tmp_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.write(file_to_hide_path, original_filename)

        # ------------------------------------------------------------------ #
        # 2. Concatenate carrier + ZIP → output (streaming, no full RAM copy) #
        # ------------------------------------------------------------------ #
        carrier_size = _stream_concat(carrier_path, tmp_zip_path, output_path)
        output_created = True

        # ------------------------------------------------------------------ #
        # 3. Patch ZIP offsets to account for the prepended carrier bytes     #
        # ------------------------------------------------------------------ #
        _fix_zip_offsets(output_path, carrier_size)

        return output_path

    except Exception:
        if output_created:
            try:
                os.remove(output_path)
            except OSError:
                pass
        raise
    finally:
        try:
            os.remove(tmp_zip_path)
        except OSError:
            pass


def extract_from_polyglot(
    polyglot_path: str,
    password: str | None = None,
) -> Tuple[bytes, str]:
    """Extract the hidden file from a polyglot file.

    Args:
        polyglot_path: Path to the polyglot file.
        password:      Optional password for encrypted archives.

    Returns:
        ``(file_data, original_filename)``

    Raises:
        ValueError: If no hidden file is found or extraction fails.
    """
    try:
        with open(polyglot_path, "rb") as fh:
            data = fh.read()

        zip_start = _locate_zip_start(data)

        if zip_start < 0 or zip_start >= len(data):
            raise ValueError("Invalid ZIP start offset derived from polyglot")

        zip_data = data[zip_start:]

        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".zip")
        try:
            os.write(tmp_fd, zip_data)
            os.close(tmp_fd)
            return _read_zip(tmp_path, password)
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to extract from polyglot: {exc}") from exc


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _stream_concat(src_a: str, src_b: str, dst: str) -> int:
    """Write ``src_a`` followed by ``src_b`` into ``dst``, streaming in
    chunks so that arbitrarily large files do not exhaust RAM.

    Returns:
        The byte-length of ``src_a`` (the carrier size / offset adjustment).
    """
    chunk = 1 << 20  # 1 MiB
    carrier_size = 0
    with open(dst, "wb") as out:
        with open(src_a, "rb") as fa:
            while True:
                buf = fa.read(chunk)
                if not buf:
                    break
                out.write(buf)
                carrier_size += len(buf)
        with open(src_b, "rb") as fb:
            while True:
                buf = fb.read(chunk)
                if not buf:
                    break
                out.write(buf)
    return carrier_size


def _locate_zip_start(data: bytes) -> int:
    """Return the absolute byte offset of the first ZIP Local File Header
    in ``data``, derived from the ZIP central directory (not from a naive
    ``find(b'PK\\x03\\x04')`` which is unreliable for ZIP-based carriers).

    Handles both standard EOCD (32-bit offsets) and ZIP64 EOCD (64-bit).
    """
    # --- Standard EOCD ---
    eocd_pos = data.rfind(_SIG_EOCD)
    if eocd_pos == -1 or len(data) - eocd_pos < 22:
        raise ValueError("No hidden file found in the polyglot (EOCD missing or truncated)")

    cd_offset_32 = struct.unpack_from("<I", data, eocd_pos + _EOCD_OFF_CD_OFFSET)[0]

    # --- ZIP64 EOCD (when the 32-bit field holds the sentinel) ---
    if cd_offset_32 == _U32_MAX:
        z64_loc_pos = data.rfind(_SIG_Z64_LOC, 0, eocd_pos)
        if z64_loc_pos == -1 or len(data) - z64_loc_pos < 20:
            raise ValueError(
                "No hidden file found: ZIP64 sentinel in EOCD but no ZIP64 "
                "EOCD locator found"
            )
        z64_eoc_offset = struct.unpack_from("<Q", data, z64_loc_pos + _Z64_LOC_OFF_Z64_EOC_OFFSET)[0]
        if z64_eoc_offset + 56 > len(data) or data[z64_eoc_offset: z64_eoc_offset + 4] != _SIG_Z64_EOC:
            raise ValueError(
                "No hidden file found: ZIP64 EOCD record not found at the "
                "offset given by the ZIP64 EOCD locator"
            )
        cd_offset = struct.unpack_from("<Q", data, z64_eoc_offset + _Z64_EOC_OFF_CD_OFFSET)[0]
    else:
        cd_offset = cd_offset_32

    # --- Walk the Central Directory to find the smallest local-header offset ---
    local_offsets: list[int] = []
    pos = cd_offset
    while pos + _CDFH_SIZE <= len(data) and data[pos: pos + 4] == _SIG_CDFH:
        lho_32 = struct.unpack_from("<I", data, pos + _CDFH_OFF_LHO)[0]
        if lho_32 == _U32_MAX:
            # Real offset is in the ZIP64 extra field (tag 0x0001)
            name_len  = struct.unpack_from("<H", data, pos + _CDFH_OFF_NAME_LEN)[0]
            extra_len = struct.unpack_from("<H", data, pos + _CDFH_OFF_EXTRA_LEN)[0]
            lho_64 = _z64_extra_lho(data, pos + _CDFH_SIZE + name_len, extra_len,
                                    struct.unpack_from("<I", data, pos + _CDFH_OFF_COMP_SIZE)[0],
                                    struct.unpack_from("<I", data, pos + _CDFH_OFF_UNCOMP_SIZE)[0])
            if lho_64 is not None:
                local_offsets.append(lho_64)
        else:
            local_offsets.append(lho_32)

        name_len    = struct.unpack_from("<H", data, pos + _CDFH_OFF_NAME_LEN)[0]
        extra_len   = struct.unpack_from("<H", data, pos + _CDFH_OFF_EXTRA_LEN)[0]
        comment_len = struct.unpack_from("<H", data, pos + _CDFH_OFF_COMMENT_LEN)[0]
        pos += _CDFH_SIZE + name_len + extra_len + comment_len

    return min(local_offsets) if local_offsets else cd_offset


def _z64_extra_lho(
    data: bytes,
    extra_start: int,
    extra_len: int,
    uncomp_32: int,
    comp_32: int,
) -> int | None:
    """Parse the ZIP64 Extra Field (tag 0x0001) and return the local-header
    offset, or ``None`` if the tag is not present.

    The ZIP64 extra block contains only the fields whose 32-bit counterpart
    holds the sentinel 0xFFFFFFFF (or 0xFFFF for the disk-number field).
    Fields appear in the following order, each 8 bytes:
      1. Uncompressed size      — present when uncomp_32 == 0xFFFFFFFF
      2. Compressed size        — present when comp_32  == 0xFFFFFFFF
      3. Local-header offset    — present when lho_32   == 0xFFFFFFFF
      4. Disk-number start      — present when disk_32  == 0xFFFF (4 bytes)
    """
    extra_end = extra_start + extra_len
    pos = extra_start
    while pos + 4 <= extra_end:
        tag      = struct.unpack_from("<H", data, pos)[0]
        blk_size = struct.unpack_from("<H", data, pos + 2)[0]
        blk_data_start = pos + 4
        blk_data_end   = blk_data_start + blk_size
        if tag == _Z64_EXTRA_TAG:
            # Calculate how many 8-byte slots precede the LHO slot
            slots_before = (1 if uncomp_32 == _U32_MAX else 0) + \
                           (1 if comp_32   == _U32_MAX else 0)
            field_offset = slots_before * 8
            if blk_data_start + field_offset + 8 <= blk_data_end:
                return struct.unpack_from("<Q", data, blk_data_start + field_offset)[0]
            return None  # Malformed block, no LHO present
        pos = blk_data_end
    return None


def _fix_zip_offsets(file_path: str, offset: int) -> None:
    """Adjust every absolute offset recorded in the ZIP/ZIP64 structures of
    ``file_path`` by adding ``offset`` bytes.

    This is called after prepending the carrier to the raw ZIP so that the
    central directory, the ZIP64 EOCD locator, and the ZIP64 EOCD record all
    point to the correct positions in the combined polyglot file.

    ZIP64 compliance (PKWARE APPNOTE 6.3.10)
    ──────────────────────────────────────────
    All four structures that store absolute offsets are patched:

    1. Standard EOCD ``PK\\x05\\x06``
       Field at +16 (uint32 LE): CD start offset.
       If already 0xFFFFFFFF (ZIP64 sentinel), leave it as-is; the real
       value is in the ZIP64 EOCD (step 3).

    2. ZIP64 EOCD Locator ``PK\\x06\\x07``
       Field at +8 (uint64 LE): absolute offset of the ZIP64 EOCD record.

    3. ZIP64 EOCD ``PK\\x06\\x06``
       Field at +48 (uint64 LE): CD start offset.

    4. Each Central Directory File Header ``PK\\x01\\x02``
       Field at +42 (uint32 LE): relative offset of the local file header.
       When this holds 0xFFFFFFFF (ZIP64 sentinel), the real 8-byte value
       lives in the ZIP64 Extra Field (tag 0x0001) inside that CD entry.

    The entire file is read into a ``bytearray``, all patches applied in
    memory, and the result written back in one atomic ``write()`` call so
    that the file is never left in a partially-patched state on disk.

    Args:
        file_path: Path to the polyglot file to patch in-place.
        offset:    Number of bytes prepended (carrier size).

    Raises:
        ValueError: If the ZIP structure is malformed or unpatchable.
    """
    with open(file_path, "r+b") as fh:
        data = bytearray(fh.read())

    # ---------------------------------------------------------------------- #
    # 1. Standard EOCD                                                        #
    # ---------------------------------------------------------------------- #
    eocd_pos = bytes(data).rfind(_SIG_EOCD)
    if eocd_pos == -1:
        return  # Not a ZIP — nothing to do (caller checked; be defensive)
    if len(data) - eocd_pos < 22:
        raise ValueError("_fix_zip_offsets: EOCD record is truncated")

    cd_offset_32 = struct.unpack_from("<I", data, eocd_pos + _EOCD_OFF_CD_OFFSET)[0]
    is_zip64 = (cd_offset_32 == _U32_MAX)

    if not is_zip64:
        new_cd_offset_32 = cd_offset_32 + offset
        if new_cd_offset_32 > _U32_MAX:
            # Overflow: write sentinel and require ZIP64 EOCD to be present
            struct.pack_into("<I", data, eocd_pos + _EOCD_OFF_CD_OFFSET, _U32_MAX)
            is_zip64 = True
        else:
            struct.pack_into("<I", data, eocd_pos + _EOCD_OFF_CD_OFFSET, new_cd_offset_32)

    # Track the final absolute CD offset for the entry-walk step below
    actual_cd_offset: int | None = None if is_zip64 else (cd_offset_32 + offset)

    # ---------------------------------------------------------------------- #
    # 2 & 3. ZIP64 EOCD Locator + ZIP64 EOCD                                 #
    # ---------------------------------------------------------------------- #
    z64_loc_pos = bytes(data).rfind(_SIG_Z64_LOC, 0, eocd_pos)

    if z64_loc_pos != -1:
        if len(data) - z64_loc_pos < 20:
            raise ValueError("_fix_zip_offsets: ZIP64 EOCD locator is truncated")

        # Read the OLD (pre-patch) offset of the ZIP64 EOCD record.
        # Important: use the ORIGINAL offset to locate the record in the
        # buffer (the buffer has not been written to disk yet).
        old_z64_eoc_offset = struct.unpack_from("<Q", data, z64_loc_pos + _Z64_LOC_OFF_Z64_EOC_OFFSET)[0]
        new_z64_eoc_offset = old_z64_eoc_offset + offset

        # Verify the ZIP64 EOCD record at the OLD position in the buffer
        if (old_z64_eoc_offset + 56 > len(data) or
                data[old_z64_eoc_offset: old_z64_eoc_offset + 4] != bytearray(_SIG_Z64_EOC)):
            # The offset in the locator does not point to a valid ZIP64 EOCD.
            # If we still have the standard CD offset, continue without ZIP64.
            if actual_cd_offset is None:
                raise ValueError(
                    "_fix_zip_offsets: ZIP64 EOCD record not found at the "
                    "position given by the ZIP64 EOCD locator"
                )
        else:
            # Patch the locator's pointer to the ZIP64 EOCD record
            struct.pack_into("<Q", data, z64_loc_pos + _Z64_LOC_OFF_Z64_EOC_OFFSET, new_z64_eoc_offset)

            # Patch the CD offset inside the ZIP64 EOCD (reading from the OLD position)
            old_z64_cd_offset = struct.unpack_from("<Q", data, old_z64_eoc_offset + _Z64_EOC_OFF_CD_OFFSET)[0]
            new_z64_cd_offset = old_z64_cd_offset + offset
            struct.pack_into("<Q", data, old_z64_eoc_offset + _Z64_EOC_OFF_CD_OFFSET, new_z64_cd_offset)

            actual_cd_offset = new_z64_cd_offset

    elif is_zip64:
        # The 32-bit field overflowed but there is no ZIP64 EOCD — malformed.
        raise ValueError(
            "_fix_zip_offsets: 32-bit CD offset overflow but no ZIP64 EOCD "
            "locator is present. The carrier may exceed 4 GiB without a "
            "ZIP64 EOCD in the hidden archive, which is unsupported."
        )

    if actual_cd_offset is None:
        raise ValueError("_fix_zip_offsets: could not determine central directory offset")

    # ---------------------------------------------------------------------- #
    # 4. Walk the Central Directory; patch each entry's local-header offset   #
    # ---------------------------------------------------------------------- #
    cd_pos = actual_cd_offset
    while cd_pos + _CDFH_SIZE <= len(data) and data[cd_pos: cd_pos + 4] == bytearray(_SIG_CDFH):
        lho_32 = struct.unpack_from("<I", data, cd_pos + _CDFH_OFF_LHO)[0]

        name_len    = struct.unpack_from("<H", data, cd_pos + _CDFH_OFF_NAME_LEN)[0]
        extra_len   = struct.unpack_from("<H", data, cd_pos + _CDFH_OFF_EXTRA_LEN)[0]
        comment_len = struct.unpack_from("<H", data, cd_pos + _CDFH_OFF_COMMENT_LEN)[0]
        next_cd_pos = cd_pos + _CDFH_SIZE + name_len + extra_len + comment_len

        if lho_32 == _U32_MAX:
            # ZIP64 sentinel: real offset lives in the ZIP64 Extra Field (tag 0x0001)
            extra_start = cd_pos + _CDFH_SIZE + name_len
            uncomp_32   = struct.unpack_from("<I", data, cd_pos + _CDFH_OFF_COMP_SIZE)[0]
            comp_32     = struct.unpack_from("<I", data, cd_pos + _CDFH_OFF_UNCOMP_SIZE)[0]
            patched = _patch_z64_extra_lho(data, extra_start, extra_len, uncomp_32, comp_32, offset)
            if not patched:
                raise ValueError(
                    f"_fix_zip_offsets: CD entry at offset {cd_pos} has a ZIP64 "
                    "sentinel for the local-header offset but no valid ZIP64 extra "
                    "field (tag 0x0001) was found."
                )
        else:
            new_lho = lho_32 + offset
            if new_lho > _U32_MAX:
                raise ValueError(
                    f"_fix_zip_offsets: local-header offset {lho_32:#010x} + "
                    f"carrier size {offset:#x} = {new_lho:#x} exceeds 32 bits "
                    "but no ZIP64 sentinel/extra-field is present in this CD "
                    "entry. The ZIP is malformed."
                )
            struct.pack_into("<I", data, cd_pos + _CDFH_OFF_LHO, new_lho)

        cd_pos = next_cd_pos

    # Atomic write: one call replaces the entire file content
    with open(file_path, "wb") as fh:
        fh.write(data)


def _patch_z64_extra_lho(
    data: bytearray,
    extra_start: int,
    extra_len: int,
    uncomp_32: int,
    comp_32: int,
    offset: int,
) -> bool:
    """Find the ZIP64 Extra Field (tag 0x0001) in ``data[extra_start:]`` and
    add ``offset`` to the local-header offset stored there in-place.

    Returns ``True`` if the field was found and patched, ``False`` otherwise.
    """
    extra_end = extra_start + extra_len
    pos = extra_start
    while pos + 4 <= extra_end:
        tag      = struct.unpack_from("<H", data, pos)[0]
        blk_size = struct.unpack_from("<H", data, pos + 2)[0]
        blk_data_start = pos + 4
        blk_data_end   = blk_data_start + blk_size
        if tag == _Z64_EXTRA_TAG:
            slots_before = (1 if uncomp_32 == _U32_MAX else 0) + \
                           (1 if comp_32   == _U32_MAX else 0)
            field_off = blk_data_start + slots_before * 8
            if field_off + 8 <= blk_data_end:
                old_lho = struct.unpack_from("<Q", data, field_off)[0]
                struct.pack_into("<Q", data, field_off, old_lho + offset)
                return True
            return False  # Block present but LHO slot would overflow it
        pos = blk_data_end
    return False


def _read_zip(zip_path: str, password: str | None) -> Tuple[bytes, str]:
    """Open a ZIP file and return ``(data, filename)`` for the first entry.

    Tries pyzipper first (supports WinZip-AES encryption), then falls back
    to the standard library.

    Raises:
        ValueError: On bad password, empty archive, or read errors.
    """
    if HAS_PYZIPPER and password:
        try:
            with pyzipper.AESZipFile(zip_path, "r") as zf:
                zf.setpassword(password.encode())
                names = zf.namelist()
                if not names:
                    raise ValueError("ZIP archive is empty")
                return zf.read(names[0]), names[0]
        except RuntimeError as exc:
            if "Bad password" in str(exc):
                raise ValueError("Incorrect password") from exc
            raise ValueError(f"ZIP read error: {exc}") from exc

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        if not names:
            raise ValueError("ZIP archive is empty")
        first = names[0]
        info  = zf.getinfo(first)
        if info.flag_bits & 0x1:   # traditional encryption flag
            if not password:
                raise ValueError("This file is password-protected. Please provide the password.")
            try:
                return zf.read(first, pwd=password.encode()), first
            except RuntimeError as exc:
                raise ValueError("Incorrect password") from exc
        return zf.read(first), first
