"""File validation utilities.

Security layers for image uploads (C-01 fix):
  1. Extension allowlist           — fast reject of clearly wrong files.
  2. Magic-byte verification       — confirms the raw bytes match the
                                     claimed format (PNG / JPEG / BMP).
  3. Pillow structural validation  — ``Image.open().verify()`` parses
                                     headers and rejects malformed /
                                     truncated / adversarial images.
  4. Pixel-count cap               — prevents decompression-bomb DoS
                                     (e.g. a 1×1 PNG that inflates to
                                     64 000 × 64 000 pixels in RAM).

``PIL.Image.MAX_IMAGE_PIXELS`` is set at *module load time* so it
applies to every ``Image.open()`` call across the whole process —
including calls inside ``steganography.py`` and ``qr_stego.py``.
"""

import logging
from PIL import Image
from werkzeug.datastructures import FileStorage

logger = logging.getLogger(__name__)

# ── Global Pillow safety cap ─────────────────────────────────────────────────
# Setting this converts Pillow's DecompressionBombWarning into a hard
# DecompressionBombError for *any* image exceeding the limit, regardless
# of which code path opens it.
MAX_PIXEL_COUNT = 100_000_000  # 100 megapixels
Image.MAX_IMAGE_PIXELS = MAX_PIXEL_COUNT

# ── File size limits (bytes) ─────────────────────────────────────────────────
MAX_IMAGE_SIZE = 10 * 1024 * 1024       # 10 MB — carrier images
MAX_HIDEABLE_FILE_SIZE = 50 * 1024 * 1024  # 50 MB — files to hide

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
ALLOWED_FILE_EXTENSIONS = {
    'txt', 'pdf', 'mp4', 'apk', 'zip',
    'jpg', 'png', 'doc', 'docx', 'xlsx',
}

# ── Magic-byte signatures ────────────────────────────────────────────────────
# Checked against the first 16 bytes of the uploaded file.  Each key is a
# byte prefix; the value is the set of extensions that signature can appear
# with.  This is deliberately kept tight — we do NOT accept SVG, TIFF, or
# WebP here because the downstream processing (LSB embedding, polyglot
# creation) only supports PNG, JPEG, and BMP.
_IMAGE_MAGIC = {
    b'\x89PNG\r\n\x1a\n': {'png'},            # PNG — full 8-byte signature
    b'\xff\xd8\xff':      {'jpg', 'jpeg'},     # JPEG — SOI + first marker byte
    b'BM':                {'bmp'},             # BMP — "BM" header
}


def validate_file(
    file: FileStorage,
    allowed_extensions: set,
    max_size: int = None,
) -> None:
    """Validate an uploaded file's name, extension, and size.

    Args:
        file:               The uploaded file.
        allowed_extensions: Set of allowed lowercase file extensions.
        max_size:           Maximum file size in bytes (optional).

    Raises:
        ValueError: If any check fails.
    """
    if not file:
        raise ValueError("No file provided.")

    if not file.filename:
        raise ValueError("File has no name.")

    if '.' not in file.filename:
        raise ValueError("File has no extension.")

    extension = file.filename.rsplit('.', 1)[1].lower()
    if extension not in allowed_extensions:
        raise ValueError(
            f"Unsupported file type '.{extension}'. "
            f"Allowed: {', '.join(sorted(allowed_extensions))}"
        )

    # Progressive size validation to prevent memory exhaustion
    if max_size:
        # First check: Use Content-Length header if available
        if file.content_length and file.content_length > max_size:
            raise ValueError(
                f"File too large. Maximum size is {max_size // (1024*1024)} MB"
            )

        # Second check: Determine actual file size by seeking to end
        # This is necessary as content_length may not always be present
        try:
            current_pos = file.stream.tell()
            file.stream.seek(0, 2)  # Seek to end
            size = file.stream.tell()
            file.stream.seek(current_pos)  # Reset to original position

            if size > max_size:
                size_mb = size / (1024 * 1024)
                max_mb = max_size / (1024 * 1024)
                raise ValueError(
                    f"File size ({size_mb:.1f} MB) exceeds maximum of {max_mb:.0f} MB"
                )
        except (OSError, IOError):
            # If we can't determine size, log warning but allow validation
            # to continue — Flask's MAX_CONTENT_LENGTH still protects us.
            pass


def validate_image(file: FileStorage) -> None:
    """Validate that *file* is a genuine, safe image.

    Performs four checks in order:
      1. Extension + size via :func:`validate_file`.
      2. Magic-byte match against the raw stream bytes.
      3. Pillow structural parse — ``Image.open().verify()`` walks the
         header/chunk tables without fully decompressing pixel data.
      4. Pixel-count cap — rejects images whose decoded dimensions
         exceed ``MAX_PIXEL_COUNT`` (set globally via
         ``Image.MAX_IMAGE_PIXELS``).

    Raises:
        ValueError: If any check fails.
    """
    # ── 1. Extension + size ──────────────────────────────────────────────
    validate_file(file, ALLOWED_IMAGE_EXTENSIONS, MAX_IMAGE_SIZE)

    extension = file.filename.rsplit('.', 1)[1].lower()

    # ── 2. Magic-byte verification ───────────────────────────────────────
    try:
        header = file.stream.read(16)
        file.stream.seek(0)
    except (OSError, IOError) as exc:
        raise ValueError(f"Could not read file header: {exc}")

    if len(header) < 2:
        raise ValueError("File is too small to be a valid image.")

    matched = False
    for signature, valid_extensions in _IMAGE_MAGIC.items():
        if header.startswith(signature):
            # Ensure the magic bytes agree with the claimed extension.
            # Prevents e.g. a JPEG file submitted as .png from slipping
            # through to code that assumes PNG structure.
            if extension not in valid_extensions:
                raise ValueError(
                    f"File content is not a valid .{extension} image "
                    f"(magic bytes indicate a different format)."
                )
            matched = True
            break

    if not matched:
        raise ValueError(
            "File content does not match any supported image format. "
            "Allowed formats: PNG, JPEG, BMP."
        )

    # ── 3. Pillow structural validation ──────────────────────────────────
    # Image.open() only reads headers; .verify() walks chunk tables
    # without fully decompressing pixel data — fast and safe.
    try:
        file.stream.seek(0)
        img = Image.open(file.stream)
        img.verify()  # raises if the structure is broken / adversarial
    except Image.DecompressionBombError:
        raise ValueError(
            f"Image dimensions exceed the maximum supported size "
            f"({MAX_PIXEL_COUNT // 1_000_000} megapixels). "
            f"Please use a smaller image."
        )
    except (Image.UnidentifiedImageError, SyntaxError):
        # SyntaxError is raised by some Pillow format parsers on
        # malformed headers (e.g. truncated PNG IHDR).
        raise ValueError(
            "The file could not be parsed as a valid image. "
            "It may be corrupted or not a genuine image file."
        )
    except Exception as exc:
        # Catch-all so that a Pillow bug doesn't bypass validation.
        logger.warning("Unexpected error during image validation: %s", exc)
        raise ValueError(
            "The file could not be validated as a safe image."
        )
    finally:
        file.stream.seek(0)

    # ── 4. Pixel-count cap ───────────────────────────────────────────────
    # Image.verify() closes the file handle in some Pillow versions, so
    # we re-open to read dimensions.  This is a cheap header-only parse.
    try:
        file.stream.seek(0)
        img = Image.open(file.stream)
        width, height = img.size
        pixel_count = width * height
        if pixel_count > MAX_PIXEL_COUNT:
            raise ValueError(
                f"Image is too large ({width}×{height} = "
                f"{pixel_count:,} pixels). Maximum is "
                f"{MAX_PIXEL_COUNT:,} pixels."
            )
    except ValueError:
        raise  # re-raise our own ValueError
    except Exception as exc:
        logger.warning("Could not read image dimensions: %s", exc)
        raise ValueError("Could not verify image dimensions.")
    finally:
        file.stream.seek(0)


def validate_hideable_file(file: FileStorage) -> None:
    """Validate that file can be hidden in an image with size limit."""
    validate_file(file, ALLOWED_FILE_EXTENSIONS, MAX_HIDEABLE_FILE_SIZE)

