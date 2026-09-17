"""API routes for steganography operations."""
from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
from PIL import Image
import os
import secrets
import uuid
from io import BytesIO
from collections import OrderedDict
import logging
import hashlib
import json
import re
import time
import threading
from typing import Any, Dict

# Import the shared limiter instance (created in extensions.py without a bound
# app so it can be imported here before the app factory runs).  This is the
# canonical Flask application-factory pattern for extensions that need to
# decorate routes in a Blueprint — the limit is registered on the function
# *before* register_blueprint() resolves endpoint names, so flask-limiter
# can correctly map it to the "api.detect_qr" / "api.health_check" endpoints.
from extensions import limiter

from utils.steganography import hide_file_in_image, extract_file_from_image
from utils.polyglot import create_polyglot, extract_from_polyglot
from utils.validators import validate_image, validate_hideable_file, MAX_STEGO_IMAGE_SIZE
from utils.qr_stego import (
    generate_qr_with_stego,
    extract_from_qr_stego,
    calculate_qr_capacity,
    get_qr_capacity_info,
    QRErrorCode,
    QRStegoError,
)


api = Blueprint('api', __name__, url_prefix='/api')
logger = logging.getLogger(__name__)

# In-memory cache for QR detection deduplication.
# Structure: {sha256_hash: (timestamp, response_data)}.  Entries expire after
# 5 s (cleaned at the top of each /qr/detect request) and the OrderedDict is
# hard-capped at _QR_CACHE_MAX so a multi-IP burst can never grow it
# unboundedly between cleanups.  SHA-256 rather than MD5 so an attacker
# cannot use a chosen-prefix collision to poison another frame's cached
# detection result.
qr_detection_cache = OrderedDict()
_qr_cache_lock = threading.Lock()
_QR_CACHE_MAX = 256
_QR_CACHE_TTL_SECONDS = 5

_SAFE_MIME_RE = re.compile(r'^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$')

# Concurrency control for Render 512 MB memory envelope.
# Deterministically limits concurrent heavy operations (hide, extract, polyglot)
# to 1 across the single Gunicorn worker process, preventing OOM spikes.
_HEAVY_OP_TIMEOUT_SECONDS: float = 30.0
_heavy_operation_semaphore = threading.BoundedSemaphore(1)


# Security: Sanitize error messages for production
SAFE_ERROR_MESSAGES = {
    'password': 'Authentication failed. Please check your password.',
    'capacity': 'The selected image is too small to hide this file.',
    'validation': 'Invalid file format or corrupted data.',
    'not_found': 'The requested file could not be found.',
    'no_hidden_data': 'No hidden data found in this file or invalid format.',
    'no_qr': 'No QR code found in the image.',
    'generic': 'An error occurred while processing your request. Please try again.'
}

MIN_PASSWORD_LENGTH = 8


def _remove_quietly(*paths):
    """Best-effort removal of temporary files.

    ``None`` entries and already-missing files are ignored, so callers can
    pass path variables that may never have been assigned (initialised to
    ``None``) or that were already cleaned up.  Used from ``finally`` blocks
    to guarantee uploaded temp files are deleted even when the operation
    raises (prevents disk-exhaustion via deliberately failing requests).
    """
    for p in paths:
        if p:
            try:
                os.remove(p)
            except OSError:
                pass


def sanitize_error(error_message: str, is_debug: bool = False) -> str:
    """Sanitize error messages to avoid leaking internal details in production.
    
    Args:
        error_message: The original error message
        is_debug: Whether app is in debug mode
        
    Returns:
        Safe error message for production, or original for debug
    """
    if is_debug:
        return error_message
    
    # Map specific errors to safe messages
    error_lower = error_message.lower()
    
    if 'no qr code' in error_lower:
        return SAFE_ERROR_MESSAGES['no_qr']
    elif 'password' in error_lower:
        return SAFE_ERROR_MESSAGES['password']
    elif 'capacity' in error_lower or 'not enough' in error_lower or 'too large' in error_lower or 'exceeds' in error_lower:
        return SAFE_ERROR_MESSAGES['capacity']
    elif (
        'no hidden' in error_lower or
        'out of range' in error_lower or
        'outside the valid range' in error_lower or
        'missing separator' in error_lower or
        'missing format' in error_lower or
        'magic' in error_lower
    ):
        return SAFE_ERROR_MESSAGES['no_hidden_data']
    elif 'not found' in error_lower:
        return SAFE_ERROR_MESSAGES['not_found']
    elif 'invalid' in error_lower or 'corrupt' in error_lower or 'failed to extract' in error_lower:
        return SAFE_ERROR_MESSAGES['validation']
    else:
        return SAFE_ERROR_MESSAGES['generic']



def _format_bytes(bytes_val: int) -> str:
    """Format a byte count as a human-readable string (e.g. '1.4 MB')."""
    if bytes_val < 1024:
        return f"{bytes_val} Bytes"
    if bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.1f} KB"
    return f"{bytes_val / (1024 * 1024):.1f} MB"


def _safe_download_name(original_filename: str) -> str:
    """Sanitize an untrusted embedded filename for use as a download name.

    ``secure_filename()`` strips path traversal and header-injection
    characters, but returns '' for fully-hostile names like
    '../../../etc/passwd'.  In that case fall back to 'extracted_file',
    re-attaching the original extension when it is a harmless alnum
    suffix so the browser can still pick a sensible handler.
    """
    safe = secure_filename(original_filename or '')
    if safe:
        return safe
    ext = os.path.splitext(original_filename or '')[1].lstrip('.')
    if ext.isalnum() and len(ext) <= 10:
        return f'extracted_file.{ext.lower()}'
    return 'extracted_file'


def _safe_upload_name(original_filename: str) -> str:
    """Sanitize an untrusted upload filename for use on disk / as embedded metadata.

    ``secure_filename()`` returns '' for fully-hostile names (all non-ASCII or
    special chars, e.g. '...', '../../.txt', or CJK-only names).  A bare
    ``{hex}_`` path with no extension then loses the file type when the name is
    embedded and later re-served.  Fall back to a generic name, re-attaching a
    harmless alnum extension when one is present.
    """
    safe = secure_filename(original_filename or '')
    if safe:
        return safe
    ext = os.path.splitext(original_filename or '')[1].lstrip('.')
    if ext.isalnum() and len(ext) <= 10:
        return f'upload.{ext.lower()}'
    return 'upload'


@api.route('/health', methods=['GET'])
@limiter.exempt
def health_check():
    """Health check endpoint.

    Exempt from rate limiting so Render's health probe (every ~10 s) never
    receives a 429 and never triggers a false-positive unhealthy status.
    The exemption is applied here — before blueprint registration — so
    flask-limiter correctly resolves it to the 'api.health_check' endpoint.
    """
    return jsonify({'status': 'ok', 'message': 'InvisioVault API is running'}), 200


@api.route('/calculate-capacity', methods=['POST'])
@limiter.limit("30 per minute", override_defaults=False)
def calculate_capacity():
    """Calculate the available steganography capacity for an image.

    Tighter limit than the global default: the UI calls this on every image
    select/drop.  30/min gives plenty of headroom for normal use while
    preventing a bot from using it as a cheap I/O-amplification vector.
    """
    try:
        # Validate request
        image = request.files.get('image')
        
        if not image:
            return jsonify({'error': 'Image file is required'}), 400
        
        # Validate image
        validate_image(image)

        # Read dimensions directly from stream (header-only, zero disk I/O, zero RGB conversion)
        image.stream.seek(0)
        with Image.open(image.stream) as img:
            total_pixels = img.width * img.height
        image.stream.seek(0)

        # Capacity calculation: 3 bits per pixel (1 bit per RGB channel)
        # Divided by 8 to convert bits to bytes
        total_capacity_bytes = (total_pixels * 3) // 8

        logger.info(f"Calculated capacity for image: {total_capacity_bytes} bytes")

        return jsonify({
            'totalCapacityBytes': total_capacity_bytes,
            'totalCapacityFormatted': _format_bytes(total_capacity_bytes)
        }), 200
    
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error calculating capacity: {str(e)}")
        safe_error = sanitize_error('An error occurred while calculating capacity', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/hide', methods=['POST'])
@limiter.limit("10 per hour", override_defaults=False)
def hide_file():
    """Hide a file in an image.

    Heavy endpoint: full LSB-steganography encode over every pixel channel,
    plus disk I/O for large files.  10/hour per IP throttles brute-force
    capacity probing and resource exhaustion while leaving normal use unaffected.
    """
    image_path = None
    file_path = None
    try:
        # Validate request
        image = request.files.get('image')
        file_to_hide = request.files.get('file')
        text_to_hide = request.form.get('text', '').strip()
        password = request.form.get('password') or None

        if not image:
            return jsonify({'error': 'Image is required'}), 400
            
        if not file_to_hide and not text_to_hide:
            return jsonify({'error': 'Either file or text is required'}), 400

        # Enforce minimum password length (P2-02)
        if password is not None and len(password) < MIN_PASSWORD_LENGTH:
            return jsonify({'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'}), 400

        # Pre-validation: format, magic, dimensions, and size checks before acquiring lock
        validate_image(image)
        if not text_to_hide:
            assert file_to_hide is not None  # guaranteed by the check at line 259
            validate_hideable_file(file_to_hide)

        # Concurrency protection: acquire bounded semaphore for heavy steganography encode
        acquired = _heavy_operation_semaphore.acquire(timeout=_HEAVY_OP_TIMEOUT_SECONDS)
        if not acquired:
            logger.warning("Heavy operation timed out waiting for semaphore on /hide")
            return jsonify({
                'error': 'The server is currently busy processing another heavy task. Please try again shortly.'
            }), 503, {'Retry-After': '5'}

        try:
            # Save files temporarily
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            
            image_filename = secure_filename(image.filename or "")
            image_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{image_filename}")
            image.save(image_path)
            
            # Handle text or file
            if text_to_hide:
                # Create temporary text file
                file_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_hidden_text.txt")
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(text_to_hide)
                clean_original_filename = "hidden_text.txt"
            else:
                assert file_to_hide is not None  # guaranteed by the check at line 259
                file_filename = _safe_upload_name(file_to_hide.filename or "")
                file_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{file_filename}")
                file_to_hide.save(file_path)
                clean_original_filename = file_filename

            # Hide file in image
            output_filename = f"{secrets.token_urlsafe(16)}.png"
            output_path = os.path.join(upload_folder, output_filename)
            hide_file_in_image(image_path, file_path, output_path, password, original_filename=clean_original_filename)

            logger.info(f"Successfully hid file in image: {output_filename}")
            return jsonify({
                'success': True,
                'message': 'File hidden successfully',
                'download_id': output_filename
            }), 200
        finally:
            _heavy_operation_semaphore.release()

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error hiding file: {str(e)}")
        safe_error = sanitize_error('An error occurred while hiding the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500
    finally:
        # Always delete the uploaded inputs — including when hide_file_in_image
        # raises (e.g. image too small), so failed requests can't leak temp files.
        _remove_quietly(image_path, file_path)


@api.route('/download/<download_id>', methods=['GET'])
@limiter.limit("30 per minute", override_defaults=False)
def download_image(download_id):
    """Download the image with hidden file.

    Low-cost file-serve endpoint.  30/min prevents download-storm abuse on
    a known or guessed download ID while keeping the UX smooth.
    """
    try:
        # Strict allowlist: token_urlsafe(16) produces exactly 22 Base64url chars.
        # Rejects URL-encoded traversal sequences, null bytes, OS separators, etc. (C-01)
        if not re.match(r'^[A-Za-z0-9_-]{22}\.png$', download_id):
            return jsonify({'error': 'Invalid download ID'}), 400

        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], download_id)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        return send_file(
            file_path,
            mimetype='image/png',
            as_attachment=True,
            download_name='invisiovault_image.png'
        )

    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        safe_error = sanitize_error('An error occurred while downloading the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/extract', methods=['POST'])
@limiter.limit("10 per hour", override_defaults=False)
def extract_file():
    """Extract a hidden file from an image.

    Heavy endpoint: full LSB decode + optional AES-GCM decryption.  The tight
    10/hour limit also mitigates password brute-forcing via repeated extraction
    attempts with different passwords.
    """
    image_path = None
    try:
        # Validate request
        image = request.files.get('image')
        password = request.form.get('password') or None

        if not image:
            return jsonify({'error': 'Image file is required'}), 400

        # Pre-validation: magic bytes, dimensions, and size checks before acquiring lock
        validate_image(image, max_size=MAX_STEGO_IMAGE_SIZE)

        # Concurrency protection: acquire bounded semaphore for heavy extraction
        acquired = _heavy_operation_semaphore.acquire(timeout=_HEAVY_OP_TIMEOUT_SECONDS)
        if not acquired:
            logger.warning("Heavy operation timed out waiting for semaphore on /extract")
            return jsonify({
                'error': 'The server is currently busy processing another heavy task. Please try again shortly.'
            }), 503, {'Retry-After': '5'}

        try:
            # Save image temporarily
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            
            image_filename = secure_filename(image.filename or "")
            image_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{image_filename}")
            image.save(image_path)

            # Extract file
            file_data, original_filename, mime_type = extract_file_from_image(image_path, password)

            # Sanitize filename from untrusted stego metadata to prevent
            # Content-Disposition header injection / path traversal (P0-03)
            safe_filename = _safe_download_name(original_filename)
            safe_mime = mime_type if (mime_type and _SAFE_MIME_RE.match(mime_type)) else "application/octet-stream"
            logger.info(f"Successfully extracted file: {safe_filename} (mimetype: {safe_mime})")

            # Configurable size-tiered response streaming:
            # Small objects (< threshold): in-memory BytesIO (eliminates disk I/O)
            # Large objects (>= threshold): file-backed streaming with response.call_on_close cleanup
            threshold = current_app.config.get('SMALL_OBJECT_THRESHOLD_BYTES', 1048576)
            if len(file_data) < threshold:
                output = BytesIO(file_data)
                output.seek(0)
                del file_data
                return send_file(
                    output,
                    mimetype=safe_mime,
                    as_attachment=True,
                    download_name=safe_filename
                )
            else:
                out_tmp_filename = f"ext_{secrets.token_hex(8)}_{safe_filename}"
                out_tmp_path = os.path.join(upload_folder, out_tmp_filename)
                with open(out_tmp_path, "wb") as f:
                    f.write(file_data)
                del file_data

                response = send_file(
                    out_tmp_path,
                    mimetype=safe_mime,
                    as_attachment=True,
                    download_name=safe_filename
                )
                response.direct_passthrough = False
                response.call_on_close(lambda: _remove_quietly(out_tmp_path))
                return response
        finally:
            _heavy_operation_semaphore.release()

    except ValueError as e:
        logger.error(f"Extraction error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error extracting file: {str(e)}")
        safe_error = sanitize_error('An error occurred while extracting the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500
    finally:
        # Always delete the uploaded stego image — including when extraction
        # fails (wrong password, corrupt data), so failed requests can't leak
        # temp files.
        _remove_quietly(image_path)


@api.route('/polyglot/create', methods=['POST'])
@limiter.limit("10 per hour", override_defaults=False)
def create_polyglot_file():
    """Create a polyglot file by appending hidden data to a carrier file.

    Heavy endpoint: ZIP construction, large file I/O, and optional AES-GCM
    encryption.  Equivalent cost to /hide — same 10/hour limit.
    """
    carrier_path = None
    file_path = None
    try:
        # Validate request
        carrier_file = request.files.get('carrier')
        file_to_hide = request.files.get('file')
        password = request.form.get('password') or None

        if not carrier_file or not carrier_file.filename:
            return jsonify({'error': 'Both carrier and file are required'}), 400

        if not file_to_hide or not file_to_hide.filename:
            return jsonify({'error': 'Both carrier and file are required'}), 400

        # Validate non-empty content and size limits
        carrier_file.stream.seek(0, 2)
        carrier_size = carrier_file.stream.tell()
        carrier_file.stream.seek(0)
        if carrier_size == 0:
            return jsonify({'error': 'Carrier file cannot be empty'}), 400
        if carrier_size > current_app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'error': 'Carrier file exceeds maximum allowed size'}), 400

        file_to_hide.stream.seek(0, 2)
        file_size = file_to_hide.stream.tell()
        file_to_hide.stream.seek(0)
        if file_size == 0:
            return jsonify({'error': 'File to hide cannot be empty'}), 400
        if file_size > current_app.config['MAX_HIDEABLE_FILE_SIZE']:
            return jsonify({'error': 'File to hide exceeds maximum allowed size'}), 400

        # Enforce minimum password length (P2-02)
        if password is not None and len(password) < MIN_PASSWORD_LENGTH:
            return jsonify({'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'}), 400

        # Concurrency protection: acquire bounded semaphore for heavy polyglot creation
        acquired = _heavy_operation_semaphore.acquire(timeout=_HEAVY_OP_TIMEOUT_SECONDS)
        if not acquired:
            logger.warning("Heavy operation timed out waiting for semaphore on /polyglot/create")
            return jsonify({
                'error': 'The server is currently busy processing another heavy task. Please try again shortly.'
            }), 503, {'Retry-After': '5'}

        try:
            # Save files temporarily
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            
            carrier_filename = _safe_upload_name(carrier_file.filename)
            file_filename = _safe_upload_name(file_to_hide.filename)
            
            carrier_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{carrier_filename}")
            file_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{file_filename}")
            
            carrier_file.save(carrier_path)
            file_to_hide.save(file_path)

            # Create polyglot file with same extension as carrier (fallback to .bin if missing or invalid)
            carrier_ext = os.path.splitext(carrier_filename)[1]
            if not carrier_ext or not carrier_ext.lstrip('.').isalnum():
                carrier_ext = '.bin'
            output_filename = f"{secrets.token_urlsafe(16)}{carrier_ext}"
            output_path = os.path.join(upload_folder, output_filename)
            
            create_polyglot(carrier_path, file_path, output_path, password, original_filename=file_filename)

            logger.info(f"Successfully created polyglot file: {output_filename}")
            return jsonify({
                'success': True,
                'message': 'Polyglot file created successfully',
                'download_id': output_filename
            }), 200
        finally:
            _heavy_operation_semaphore.release()

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error creating polyglot: {str(e)}")
        safe_error = sanitize_error('An error occurred while creating the polyglot file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500
    finally:
        # Always delete the uploaded inputs — including when create_polyglot
        # raises, so failed requests can't leak temp files.
        _remove_quietly(carrier_path, file_path)


@api.route('/polyglot/download/<download_id>', methods=['GET'])
@limiter.limit("30 per minute", override_defaults=False)
def download_polyglot(download_id):
    """Download the polyglot file.

    Low-cost file-serve endpoint.  30/min mirrors the /download limit.
    """
    try:
        # Validate filename: must be token_urlsafe(16) (22 chars) + dot + extension.
        # This prevents path traversal and cross-user file enumeration (P2-07).
        if not re.match(r'^[A-Za-z0-9_-]{22}\.[a-zA-Z0-9]+$', download_id):
            return jsonify({'error': 'Invalid download ID'}), 400

        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], download_id)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        return send_file(
            file_path,
            as_attachment=True,
            download_name=f'polyglot_{download_id}'
        )

    except Exception as e:
        logger.error(f"Error downloading polyglot: {str(e)}")
        safe_error = sanitize_error('An error occurred while downloading the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/polyglot/extract', methods=['POST'])
@limiter.limit("10 per hour", override_defaults=False)
def extract_from_polyglot_file():
    """Extract hidden file from a polyglot file.

    Heavy endpoint: ZIP parse, optional AES-GCM decryption.  Same cost and
    password-oracle risk as /extract — same 10/hour limit.
    """
    polyglot_path = None
    try:
        # Validate request
        polyglot_file = request.files.get('file')
        password = request.form.get('password') or None

        if not polyglot_file or not polyglot_file.filename:
            return jsonify({'error': 'Polyglot file is required'}), 400

        polyglot_file.stream.seek(0, 2)
        poly_size = polyglot_file.stream.tell()
        polyglot_file.stream.seek(0)
        if poly_size == 0:
            return jsonify({'error': 'Polyglot file cannot be empty'}), 400
        if poly_size > current_app.config['MAX_CONTENT_LENGTH']:
            return jsonify({'error': 'Polyglot file exceeds maximum allowed size'}), 400

        # Concurrency protection: acquire bounded semaphore for heavy polyglot extraction
        acquired = _heavy_operation_semaphore.acquire(timeout=_HEAVY_OP_TIMEOUT_SECONDS)
        if not acquired:
            logger.warning("Heavy operation timed out waiting for semaphore on /polyglot/extract")
            return jsonify({
                'error': 'The server is currently busy processing another heavy task. Please try again shortly.'
            }), 503, {'Retry-After': '5'}

        try:
            # Save file temporarily
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            
            polyglot_filename = secure_filename(polyglot_file.filename)
            polyglot_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{polyglot_filename}")
            polyglot_file.save(polyglot_path)

            # Extract file
            file_data, original_filename = extract_from_polyglot(polyglot_path, password)

            # Sanitize filename from untrusted ZIP/polyglot metadata to prevent
            # Content-Disposition header injection / path traversal (P0-03)
            safe_filename = _safe_download_name(original_filename)
            logger.info(f"Successfully extracted from polyglot: {safe_filename}")

            # Configurable size-tiered response streaming:
            # Small objects (< threshold): in-memory BytesIO
            # Large objects (>= threshold): file-backed streaming with response.call_on_close cleanup
            threshold = current_app.config.get('SMALL_OBJECT_THRESHOLD_BYTES', 1048576)
            if len(file_data) < threshold:
                output = BytesIO(file_data)
                output.seek(0)
                del file_data
                return send_file(
                    output,
                    as_attachment=True,
                    download_name=safe_filename
                )
            else:
                out_tmp_filename = f"ext_poly_{secrets.token_hex(8)}_{safe_filename}"
                out_tmp_path = os.path.join(upload_folder, out_tmp_filename)
                with open(out_tmp_path, "wb") as f:
                    f.write(file_data)
                del file_data

                response = send_file(
                    out_tmp_path,
                    as_attachment=True,
                    download_name=safe_filename
                )
                response.direct_passthrough = False
                response.call_on_close(lambda: _remove_quietly(out_tmp_path))
                return response
        finally:
            _heavy_operation_semaphore.release()

    except ValueError as e:
        logger.error(f"Polyglot extraction error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error extracting from polyglot: {str(e)}")
        safe_error = sanitize_error('An error occurred while extracting the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500
    finally:
        # Always delete the uploaded polyglot — including when extraction
        # fails (wrong password, no hidden data), so failed requests can't
        # leak temp files.
        _remove_quietly(polyglot_path)


@api.route('/qr/generate', methods=['POST'])
@limiter.limit("20 per hour", override_defaults=False)
def generate_qr_code():
    """Generate a customized QR code with hidden steganographic text.

    Medium-cost endpoint: QR matrix generation + AES-GCM encryption +
    optional logo compositing.  20/hour allows reasonable user activity
    while preventing bulk QR generation abuse.
    """
    logo_path = None
    try:
        # Validate request
        public_data = request.form.get('public_data', '').strip()
        secret_text = request.form.get('secret_text', '').strip()
        password = request.form.get('password') or None
        fg_color = request.form.get('fg_color', '#000000').strip()
        bg_color = request.form.get('bg_color', '#FFFFFF').strip()
        try:
            scale = int(request.form.get('scale') or 10)
        except (ValueError, TypeError):
            scale = 10
        
        if not public_data:
            return jsonify({'error': 'Public data (QR content) is required'}), 400
        
        if not secret_text:
            return jsonify({'error': 'Secret text is required'}), 400

        # Enforce minimum password length (P2-02)
        if password is not None and len(password) < MIN_PASSWORD_LENGTH:
            return jsonify({'error': f'Password must be at least {MIN_PASSWORD_LENGTH} characters long'}), 400
        
        # Validate and normalize colors (supports 3-char and 6-char hex)
        def _sanitize_color(c: str, default: str) -> str:
            c = c.strip()
            if re.match(r'^#[0-9A-Fa-f]{3}$', c):
                return '#' + ''.join(ch * 2 for ch in c[1:]).upper()
            if re.match(r'^#[0-9A-Fa-f]{6}$', c):
                return c.upper()
            return default

        fg_color = _sanitize_color(fg_color, '#000000')
        bg_color = _sanitize_color(bg_color, '#FFFFFF')
        
        # Validate scale
        if scale < 1 or scale > 50:
            scale = 10
        
        # Handle optional logo
        logo_file = request.files.get('logo')

        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)

        if logo_file:
            try:
                validate_image(logo_file)
                logo_filename = secure_filename(logo_file.filename or "")
                logo_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{logo_filename}")
                logo_file.save(logo_path)
            except ValueError:
                # If logo validation fails, continue without logo
                logo_path = None

        method = request.form.get('method', 'visual').strip().lower()

        # Generate QR code with steganography (visual mode only)
        output_filename = f"{secrets.token_urlsafe(16)}_qr.png"
        output_path = os.path.join(upload_folder, output_filename)

        generate_qr_with_stego(
            public_data=public_data,
            secret_text=secret_text,
            output_path=output_path,
            password=password,
            fg_color=fg_color,
            bg_color=bg_color,
            scale=scale,
            logo_path=logo_path,
            method=method,
        )

        logger.info(f"Successfully generated QR code: {output_filename}")
        return jsonify({
            'success': True,
            'message': 'QR code generated successfully',
            'download_id': output_filename
        }), 200

    except QRStegoError as e:
        logger.error(f"QR generation stego error: {str(e)}")
        if e.error_code in (QRErrorCode.CAPACITY_EXCEEDED, QRErrorCode.QR_INVALID):
            return jsonify({'error': str(e)}), 400
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except ValueError as e:
        logger.error(f"QR generation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}")
        safe_error = sanitize_error('An error occurred while generating the QR code', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500
    finally:
        # Always delete the uploaded logo — including when scale parsing or
        # QR generation raises, so failed requests can't leak temp files.
        _remove_quietly(logo_path)


@api.route('/qr/download/<download_id>', methods=['GET'])
@limiter.limit("30 per minute", override_defaults=False)
def download_qr_code(download_id):
    """Download the generated QR code.

    Low-cost file-serve endpoint.  30/min mirrors the other download limits.
    """
    try:
        # Strict allowlist: token_urlsafe(16) produces exactly 22 Base64url chars.
        # Rejects URL-encoded traversal sequences, null bytes, OS separators, etc. (C-01)
        if not re.match(r'^[A-Za-z0-9_-]{22}_qr\.png$', download_id):
            return jsonify({'error': 'Invalid download ID'}), 400

        file_path = os.path.abspath(os.path.join(current_app.config['UPLOAD_FOLDER'], download_id))
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        return send_file(
            file_path,
            mimetype='image/png',
            as_attachment=True,
            download_name='invisiovault_qr.png'
        )

    except Exception as e:
        logger.error(f"Error downloading QR code: {str(e)}")
        safe_error = sanitize_error('An error occurred while downloading the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/qr/scan', methods=['POST'])
@limiter.limit("60 per hour", override_defaults=False)
def scan_qr_code():
    """Scan a QR code and extract both public and hidden data.

    Medium-cost endpoint: full QR decode + AES-GCM decryption + stego pixel
    scan.  20/hour prevents password-oracle abuse via repeated scan attempts
    while accommodating legitimate multi-scan workflows.
    """
    qr_path = None
    cache_key: str | None = None  # set after image hash; None means cache wasn't reached
    debug_sink: Dict[str, Any] = {}  # initialised early so except handler can read it
    debug_capture_enabled = os.getenv("DEBUG_CAMERA_CAPTURE", "false").strip().lower() == "true"
    try:
        # Generate unique non-sensitive scan trace ID
        camera_scan_id = secrets.token_hex(4)
        debug_sink["cameraScanId"] = camera_scan_id

        # Validate request
        qr_image = request.files.get('image')
        password = request.form.get('password') or None
        raw_qr_data = request.form.get('raw_qr_data') or request.form.get('rawQrData') or None
        corners_raw = request.form.get('corners') or None
        version_raw = request.form.get('version') or None

        client_corners = None
        if corners_raw:
            try:
                client_corners = json.loads(corners_raw) if isinstance(corners_raw, str) else corners_raw
            except (json.JSONDecodeError, TypeError, ValueError) as err:
                logger.warning(f"QR scan [{camera_scan_id}]: Failed to parse client corners: {err}")

        client_version = None
        if version_raw is not None:
            try:
                client_version = int(version_raw)
            except (ValueError, TypeError):
                pass
        
        logger.info(
            f"QR scan [{camera_scan_id}]: Request received. password={password is not None}, "
            f"raw_data={raw_qr_data is not None}, client_corners={client_corners is not None}, "
            f"client_version={client_version}"
        )
        
        if not qr_image:
            logger.warning(f"QR scan [{camera_scan_id}]: No image provided in request")
            return jsonify({'error': 'QR code image is required', 'cameraScanId': camera_scan_id, 'failureReason': 'NO_QR'}), 400
        
        validate_image(qr_image)
        logger.debug(f"QR scan [{camera_scan_id}]: Image validation passed")

        # Ephemeral debug frame capture per scan (strictly development only)
        if debug_capture_enabled:
            try:
                debug_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], "debug")
                os.makedirs(debug_dir, exist_ok=True)
                debug_img_path = os.path.join(debug_dir, f"debug_camera_{camera_scan_id}.png")
                debug_meta_path = os.path.join(debug_dir, f"debug_camera_{camera_scan_id}.json")
                latest_img_path = os.path.join(debug_dir, "debug_camera_latest.png")
                latest_meta_path = os.path.join(debug_dir, "debug_camera_latest.json")

                qr_image.stream.seek(0)
                img_content = qr_image.stream.read()
                qr_image.stream.seek(0)

                with open(debug_img_path, "wb") as f_dbg:
                    f_dbg.write(img_content)
                with open(latest_img_path, "wb") as f_latest:
                    f_latest.write(img_content)

                meta_content = {
                    "camera_scan_id": camera_scan_id,
                    "timestamp": time.time(),
                    "raw_qr_data": raw_qr_data,
                    "client_version": client_version,
                    "corners": client_corners,
                }
                with open(debug_meta_path, "w", encoding="utf-8") as f_meta:
                    json.dump(meta_content, f_meta, indent=2)
                with open(latest_meta_path, "w", encoding="utf-8") as f_meta_latest:
                    json.dump(meta_content, f_meta_latest, indent=2)

                logger.debug("QR scan [%s]: Saved ephemeral debug frame to %s", camera_scan_id, debug_img_path)
            except Exception as d_err:
                logger.warning("QR scan [%s]: Failed to save debug camera capture: %s", camera_scan_id, d_err)

        # Burst deduplication cache check (prevents camera frame spam from burning CPU)
        img_bytes = qr_image.read()
        qr_image.seek(0)
        cache_key = hashlib.sha256(
            img_bytes
            + (password or "").encode("utf-8")
            + (raw_qr_data or "").encode("utf-8")
            + (corners_raw or "").encode("utf-8")
            + (version_raw or "").encode("utf-8")
        ).hexdigest()
        now = time.time()

        with _qr_cache_lock:
            # Clean expired entries
            expired = [k for k, v in qr_detection_cache.items() if now - v[0] > _QR_CACHE_TTL_SECONDS]
            for k in expired:
                del qr_detection_cache[k]

            if cache_key in qr_detection_cache:
                cached_time, cached_payload = qr_detection_cache[cache_key]
                if now - cached_time < 2.0:
                    logger.debug("QR scan [%s]: Deduplication cache hit for key %s...", camera_scan_id, cache_key[:8])
                    status_code = cached_payload.get('_status_code', 200)
                    resp = {k: v for k, v in cached_payload.items() if k != '_status_code'}
                    resp['cameraScanId'] = camera_scan_id
                    return jsonify(resp), status_code

        # Save image temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)

        qr_filename = secure_filename(qr_image.filename or "")
        qr_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{qr_filename}")
        qr_image.save(qr_path)
        logger.debug(f'QR scan [{camera_scan_id}]: Saved image to {qr_path}')

        # Extract both public and secret data
        logger.info(f'QR scan [{camera_scan_id}]: Extracting data from QR code...')
        public_data, secret_data = extract_from_qr_stego(
            qr_path,
            password=password,
            raw_qr_text=raw_qr_data,
            client_corners=client_corners,
            client_version=client_version,
            debug_info=debug_sink,
        )

        logger.info(
            f"QR scan [{camera_scan_id}]: Extraction completed. "
            f"Public data length: {len(public_data)}, Secret present: {bool(secret_data)}, "
            f"Geometry: {debug_sink.get('geometrySource')}, Failure reason: {debug_sink.get('failureReason')}"
        )
        resp_data: Dict[str, Any] = {
            'success': True,
            'cameraScanId': camera_scan_id,
            'publicData': public_data,
            'secretData': secret_data,
            'hasPassword': password is not None
        }

        with _qr_cache_lock:
            # Cache only the non-debug fields — debug trace belongs to this
            # specific request and must not be served to other callers via cache.
            qr_detection_cache[cache_key] = (now, resp_data.copy())
            while len(qr_detection_cache) > _QR_CACHE_MAX:
                qr_detection_cache.popitem(last=False)

        if current_app.config.get('DEBUG') or debug_capture_enabled:
            resp_data['debug'] = debug_sink

        return jsonify(resp_data), 200

    except ValueError as e:
        logger.error(f"QR scan: Validation error - {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])

        err_data = {
            'error': safe_error,
            '_status_code': 400,
            'cameraScanId': debug_sink.get('cameraScanId', 'unknown')
        }
        if 'password' in str(e).lower():
            logger.warning('QR scan: Password required but not provided or incorrect')
            err_data['passwordRequired'] = True
            err_data['failureReason'] = 'WRONG_PASSWORD'
        else:
            err_data['failureReason'] = debug_sink.get('failureReason', 'EXTRACTION_EXCEPTION')

        if cache_key is not None:
            with _qr_cache_lock:
                qr_detection_cache[cache_key] = (time.time(), err_data)

        resp = {k: v for k, v in err_data.items() if k != '_status_code'}
        return jsonify(resp), 400
    except Exception as e:
        logger.error(f"QR scan: Unexpected error - {str(e)}", exc_info=True)
        safe_error = sanitize_error('An error occurred while scanning the QR code', current_app.config['DEBUG'])
        return jsonify({
            'error': safe_error,
            'cameraScanId': debug_sink.get('cameraScanId', 'unknown'),
            'failureReason': 'EXTRACTION_EXCEPTION',
            'exceptionType': type(e).__name__ if current_app.config.get('DEBUG') else None
        }), 500
    finally:
        # Final cleanup in case of early exit
        if qr_path and os.path.exists(qr_path):
            try:
                os.remove(qr_path)
            except Exception:
                pass


@api.route('/qr/extract', methods=['POST'])
@limiter.limit("20 per hour", override_defaults=False)
def extract_qr_manual():
    """Manually extract hidden data from QR code (alias for /qr/scan).

    Maintained for backward compatibility; delegates directly to scan_qr_code().
    """
    return scan_qr_code()


@api.route('/qr/capacity', methods=['POST'])
@limiter.limit("60 per minute", override_defaults=False)
def qr_capacity():
    """Calculate steganography capacity for a QR code.

    Negligible cost: pure arithmetic, no I/O.  60/min matches /qr/detect
    since this is also polled on user input during QR setup.
    """
    try:
        public_data = request.form.get('public_data', '')
        try:
            scale = int(request.form.get('scale') or 15)
        except (ValueError, TypeError):
            scale = 15

        info = get_qr_capacity_info(public_data, scale)
        capacity = info["safeCapacityBytes"]

        return jsonify({
            'totalCapacityBytes': capacity,
            'totalCapacityFormatted': _format_bytes(capacity),
            'safeCapacityBytes': capacity,
            'maxSafeVersion': info["maxSafeVersion"],
            'recommendedErrorCorrection': info["recommendedErrorCorrection"],
            'recommendedVersion': info["recommendedVersion"]
        }), 200

    except Exception as e:
        logger.error(f"Error calculating QR capacity: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400


@api.route('/qr/detect', methods=['POST'])
@limiter.limit("60 per minute")
def detect_qr():
    """Quick QR detection endpoint for camera scanner - just checks if QR exists."""
    try:
        # Validate image file is present
        if 'image' not in request.files:
            logger.debug('QR detection: No image in request')
            return jsonify({'detected': False}), 200
        
        image_file = request.files['image']
        
        if not image_file or image_file.filename == '':
            logger.debug('QR detection: Empty image file')
            return jsonify({'detected': False}), 200
        
        # Hash for deduplication. SHA-256 collision resistance prevents poisoning.
        image_data = image_file.read()
        image_hash = hashlib.sha256(image_data).hexdigest()
        current_time = time.time()

        with _qr_cache_lock:
            # Clean up expired cache entries
            expired_keys = [k for k, v in qr_detection_cache.items()
                            if current_time - v[0] > _QR_CACHE_TTL_SECONDS]
            for k in expired_keys:
                del qr_detection_cache[k]
                logger.debug(f'QR detection: Cleaned up expired cache entry {k[:8]}...')
            
            # Check cache for recent identical request (within 1 second)
            if image_hash in qr_detection_cache:
                cache_timestamp, cached_response = qr_detection_cache[image_hash]
                if current_time - cache_timestamp < 1.0:
                    logger.debug(f'QR detection: Cache hit for hash {image_hash[:8]}...')
                    return jsonify(cached_response), 200

        # Try to decode QR code directly in memory (zero disk I/O, zero file locks)
        try:
            import importlib
            zxingcpp = importlib.import_module("zxingcpp")
            
            stream_buf = BytesIO(image_data)
            with Image.open(stream_buf) as img:
                decoded_objects = zxingcpp.read_barcodes(img)
            detected = len(decoded_objects) > 0
            
            if detected:
                logger.info('QR detection: QR code detected in frame')
            else:
                logger.debug('QR detection: No QR code in frame')
            
            response_data = {'detected': detected, 'success': True}
            with _qr_cache_lock:
                qr_detection_cache[image_hash] = (current_time, response_data)
                while len(qr_detection_cache) > _QR_CACHE_MAX:
                    qr_detection_cache.popitem(last=False)
            logger.debug(f'QR detection: Cached response for hash {image_hash[:8]}...')
            
            return jsonify(response_data), 200
            
        except ImportError as import_error:
            logger.error(f'QR detection: Missing dependency - {str(import_error)}')
            return jsonify({
                'detected': False, 
                'error': 'QR detection library not available'
            }), 500
            
        except Exception as decode_error:
            logger.warning(f'QR detection: Decode failed - {str(decode_error)}')
            return jsonify({'detected': False}), 200
                
    except Exception as e:
        logger.error(f'QR detection: Unexpected error - {str(e)}', exc_info=True)
        return jsonify({'detected': False}), 200


@api.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    max_size = current_app.config.get('MAX_CONTENT_LENGTH', 64 * 1024 * 1024)
    max_size_mb = max_size // (1024 * 1024)
    return jsonify({
        'error': f'Request too large. Maximum total size is {max_size_mb} MB. '
                 f'Individual limits: Images (10 MB), Files (50 MB)'
    }), 413

