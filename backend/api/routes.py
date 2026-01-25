"""API routes for steganography operations."""
from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
import os
import secrets
import uuid
from io import BytesIO
import logging
import hashlib
import time

from utils.steganography import hide_file_in_image, extract_file_from_image
from utils.polyglot import create_polyglot, extract_from_polyglot
from utils.validators import validate_image, validate_hideable_file
from utils.qr_stego import (
    generate_qr_with_stego,
    extract_from_qr_stego,
    calculate_qr_capacity,
    decode_qr_only
)


api = Blueprint('api', __name__, url_prefix='/api')
logger = logging.getLogger(__name__)

# In-memory cache for QR detection deduplication
# Structure: {md5_hash: (timestamp, response_data)}
qr_detection_cache = {}


# Security: Sanitize error messages for production
SAFE_ERROR_MESSAGES = {
    'password': 'Authentication failed. Please check your password.',
    'capacity': 'The selected image is too small to hide this file.',
    'validation': 'Invalid file format or corrupted data.',
    'not_found': 'The requested file could not be found.',
    'generic': 'An error occurred while processing your request. Please try again.'
}


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
    
    if 'password' in error_lower or 'incorrect password' in error_lower:
        return SAFE_ERROR_MESSAGES['password']
    elif 'capacity' in error_lower or 'not enough' in error_lower:
        return SAFE_ERROR_MESSAGES['capacity']
    elif 'invalid' in error_lower or 'corrupt' in error_lower or 'failed to extract' in error_lower:
        return SAFE_ERROR_MESSAGES['validation']
    elif 'not found' in error_lower:
        return SAFE_ERROR_MESSAGES['not_found']
    else:
        return SAFE_ERROR_MESSAGES['generic']


def get_limiter():
    """Get the limiter instance from the current app."""
    return current_app.limiter


@api.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'message': 'InvisioVault API is running'}), 200


@api.route('/calculate-capacity', methods=['POST'])
def calculate_capacity():
    """Calculate the available steganography capacity for an image."""
    try:
        # Validate request
        image = request.files.get('image')
        
        if not image:
            return jsonify({'error': 'Image file is required'}), 400
        
        # Validate image
        validate_image(image)
        
        # Save image temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        image_filename = secure_filename(image.filename)
        image_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{image_filename}")
        image.save(image_path)
        
        try:
            # Open image and calculate capacity
            from PIL import Image
            img = Image.open(image_path).convert("RGB")
            total_pixels = len(list(img.getdata()))
            
            # Capacity calculation: 3 bits per pixel (1 bit per RGB channel)
            # Divided by 8 to convert bits to bytes
            total_capacity_bytes = (total_pixels * 3) // 8
            
            # Format for display
            def format_bytes(bytes_val):
                if bytes_val < 1024:
                    return f"{bytes_val} Bytes"
                elif bytes_val < 1024 * 1024:
                    return f"{bytes_val / 1024:.1f} KB"
                else:
                    return f"{bytes_val / (1024 * 1024):.1f} MB"
            
            logger.info(f"Calculated capacity for image: {total_capacity_bytes} bytes")
            
            return jsonify({
                'totalCapacityBytes': total_capacity_bytes,
                'totalCapacityFormatted': format_bytes(total_capacity_bytes)
            }), 200
            
        finally:
            # Clean up temporary file
            if os.path.exists(image_path):
                os.remove(image_path)
    
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error calculating capacity: {str(e)}")
        safe_error = sanitize_error('An error occurred while calculating capacity', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/hide', methods=['POST'])
def hide_file():
    """Hide a file in an image."""
    # Rate limiting handled at app level
    try:
        # Validate request
        image = request.files.get('image')
        file_to_hide = request.files.get('file')
        text_to_hide = request.form.get('text', '').strip()
        password = request.form.get('password', '').strip() or None

        if not image:
            return jsonify({'error': 'Image is required'}), 400
            
        if not file_to_hide and not text_to_hide:
            return jsonify({'error': 'Either file or text is required'}), 400

        # Validate image
        validate_image(image)

        # Save files temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        image_filename = secure_filename(image.filename)
        image_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{image_filename}")
        image.save(image_path)
        
        # Handle text or file
        if text_to_hide:
            # Create temporary text file
            file_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_hidden_text.txt")
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(text_to_hide)
        else:
            # Validate and save uploaded file
            validate_hideable_file(file_to_hide)
            file_filename = secure_filename(file_to_hide.filename)
            file_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{file_filename}")
            file_to_hide.save(file_path)

        # Hide file in image
        output_filename = f"{secrets.token_urlsafe(16)}.png"
        output_path = os.path.join(upload_folder, output_filename)
        hide_file_in_image(image_path, file_path, output_path, password)

        # Clean up input files
        os.remove(image_path)
        os.remove(file_path)

        logger.info(f"Successfully hid file in image: {output_filename}")
        return jsonify({
            'success': True,
            'message': 'File hidden successfully',
            'download_id': output_filename
        }), 200

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error hiding file: {str(e)}")
        safe_error = sanitize_error('An error occurred while hiding the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/download/<download_id>', methods=['GET'])
def download_image(download_id):
    """Download the image with hidden file."""
    try:
        # Validate filename to prevent path traversal
        if not download_id.endswith('.png') or '/' in download_id or '\\' in download_id:
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
def extract_file():
    """Extract a hidden file from an image."""
    try:
        # Validate request
        image = request.files.get('image')
        password = request.form.get('password', '').strip() or None

        if not image:
            return jsonify({'error': 'Image file is required'}), 400

        validate_image(image)

        # Save image temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        image_filename = secure_filename(image.filename)
        image_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{image_filename}")
        image.save(image_path)

        # Extract file
        file_data, original_filename, mime_type = extract_file_from_image(image_path, password)

        # Clean up
        os.remove(image_path)

        # Send extracted file
        output = BytesIO(file_data)
        output.seek(0)

        logger.info(f"Successfully extracted file: {original_filename}")
        return send_file(
            output,
            mimetype=mime_type,
            as_attachment=True,
            download_name=original_filename
        )

    except ValueError as e:
        logger.error(f"Extraction error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error extracting file: {str(e)}")
        safe_error = sanitize_error('An error occurred while extracting the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/polyglot/create', methods=['POST'])
def create_polyglot_file():
    """Create a polyglot file by appending hidden data to a carrier file."""
    try:
        # Validate request
        carrier_file = request.files.get('carrier')
        file_to_hide = request.files.get('file')
        password = request.form.get('password', '').strip() or None

        if not carrier_file or not file_to_hide:
            return jsonify({'error': 'Both carrier and file are required'}), 400

        # Save files temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        carrier_filename = secure_filename(carrier_file.filename)
        file_filename = secure_filename(file_to_hide.filename)
        
        carrier_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{carrier_filename}")
        file_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{file_filename}")
        
        carrier_file.save(carrier_path)
        file_to_hide.save(file_path)

        # Create polyglot file with same extension as carrier
        carrier_ext = os.path.splitext(carrier_filename)[1]
        output_filename = f"{secrets.token_urlsafe(16)}{carrier_ext}"
        output_path = os.path.join(upload_folder, output_filename)
        
        create_polyglot(carrier_path, file_path, output_path, password)

        # Clean up input files
        os.remove(carrier_path)
        os.remove(file_path)

        logger.info(f"Successfully created polyglot file: {output_filename}")
        return jsonify({
            'success': True,
            'message': 'Polyglot file created successfully',
            'download_id': output_filename
        }), 200

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error creating polyglot: {str(e)}")
        safe_error = sanitize_error('An error occurred while creating the polyglot file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/polyglot/download/<download_id>', methods=['GET'])
def download_polyglot(download_id):
    """Download the polyglot file."""
    try:
        # Validate filename to prevent path traversal
        if '/' in download_id or '\\' in download_id:
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
def extract_from_polyglot_file():
    """Extract hidden file from a polyglot file."""
    try:
        # Validate request
        polyglot_file = request.files.get('file')
        password = request.form.get('password', '').strip() or None

        if not polyglot_file:
            return jsonify({'error': 'Polyglot file is required'}), 400

        # Save file temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        polyglot_filename = secure_filename(polyglot_file.filename)
        polyglot_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{polyglot_filename}")
        polyglot_file.save(polyglot_path)

        # Extract file
        file_data, original_filename = extract_from_polyglot(polyglot_path, password)

        # Clean up
        os.remove(polyglot_path)

        # Send extracted file
        output = BytesIO(file_data)
        output.seek(0)

        logger.info(f"Successfully extracted from polyglot: {original_filename}")
        return send_file(
            output,
            as_attachment=True,
            download_name=original_filename
        )

    except ValueError as e:
        logger.error(f"Polyglot extraction error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error extracting from polyglot: {str(e)}")
        safe_error = sanitize_error('An error occurred while extracting the file', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/qr/generate', methods=['POST'])
def generate_qr_code():
    """Generate a customized QR code with hidden steganographic text."""
    try:
        # Validate request
        public_data = request.form.get('public_data', '').strip()
        secret_text = request.form.get('secret_text', '').strip()
        password = request.form.get('password', '').strip() or None
        fg_color = request.form.get('fg_color', '#000000').strip()
        bg_color = request.form.get('bg_color', '#FFFFFF').strip()
        scale = int(request.form.get('scale', 10))
        
        if not public_data:
            return jsonify({'error': 'Public data (QR content) is required'}), 400
        
        if not secret_text:
            return jsonify({'error': 'Secret text is required'}), 400
        
        # Validate colors (basic hex color validation)
        if not (fg_color.startswith('#') and len(fg_color) == 7):
            fg_color = '#000000'
        if not (bg_color.startswith('#') and len(bg_color) == 7):
            bg_color = '#FFFFFF'
        
        # Validate scale
        if scale < 1 or scale > 50:
            scale = 10
        
        # Handle optional logo
        logo_file = request.files.get('logo')
        logo_path = None
        
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        if logo_file:
            try:
                validate_image(logo_file)
                logo_filename = secure_filename(logo_file.filename)
                logo_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{logo_filename}")
                logo_file.save(logo_path)
            except ValueError:
                # If logo validation fails, continue without logo
                logo_path = None
        
        # Generate QR code with steganography
        output_filename = f"{secrets.token_urlsafe(16)}_qr.png"
        output_path = os.path.join(upload_folder, output_filename)
        
        try:
            generate_qr_with_stego(
                public_data=public_data,
                secret_text=secret_text,
                output_path=output_path,
                password=password,
                fg_color=fg_color,
                bg_color=bg_color,
                scale=scale,
                logo_path=logo_path
            )
            
            logger.info(f"Successfully generated QR code: {output_filename}")
            return jsonify({
                'success': True,
                'message': 'QR code generated successfully',
                'download_id': output_filename
            }), 200
        finally:
            # Clean up logo file if it was uploaded
            if logo_path and os.path.exists(logo_path):
                os.remove(logo_path)
    
    except ValueError as e:
        logger.error(f"QR generation error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error generating QR code: {str(e)}")
        safe_error = sanitize_error('An error occurred while generating the QR code', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/qr/download/<download_id>', methods=['GET'])
def download_qr_code(download_id):
    """Download the generated QR code."""
    try:
        # Validate filename to prevent path traversal
        if not download_id.endswith('_qr.png') or '/' in download_id or '\\' in download_id:
            return jsonify({'error': 'Invalid download ID'}), 400

        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], download_id)
        
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
def scan_qr_code():
    """Scan a QR code and extract both public and hidden data."""
    qr_path = None
    try:
        # Validate request
        qr_image = request.files.get('image')
        password = request.form.get('password', '').strip() or None
        
        logger.info(f'QR scan: Request received, password provided: {password is not None}')
        
        if not qr_image:
            logger.warning('QR scan: No image provided in request')
            return jsonify({'error': 'QR code image is required'}), 400
        
        validate_image(qr_image)
        logger.debug('QR scan: Image validation passed')
        
        # Save image temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        qr_filename = secure_filename(qr_image.filename)
        qr_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{qr_filename}")
        qr_image.save(qr_path)
        logger.debug(f'QR scan: Saved image to {qr_path}')
        
        try:
            # Extract both public and secret data
            logger.info('QR scan: Extracting data from QR code...')
            public_data, secret_data = extract_from_qr_stego(qr_path, password)
            
            logger.info(f'QR scan: Successfully extracted data. Public data length: {len(public_data)}, Secret data present: {bool(secret_data)}')
            return jsonify({
                'success': True,
                'publicData': public_data,
                'secretData': secret_data,
                'hasPassword': password is not None
            }), 200
        finally:
            # Clean up
            if os.path.exists(qr_path):
                os.remove(qr_path)
                logger.debug('QR scan: Cleaned up temporary file')
    
    except ValueError as e:
        logger.error(f'QR scan: Validation error - {str(e)}')
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        
        # Check if password is required
        if 'password' in str(e).lower():
            logger.warning('QR scan: Password required but not provided or incorrect')
            return jsonify({'error': safe_error, 'passwordRequired': True}), 400
        
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f'QR scan: Unexpected error - {str(e)}', exc_info=True)
        safe_error = sanitize_error('An error occurred while scanning the QR code', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500
    finally:
        # Final cleanup in case of early exit
        if qr_path and os.path.exists(qr_path):
            try:
                os.remove(qr_path)
            except Exception:
                pass


@api.route('/qr/extract', methods=['POST'])
def extract_qr_manual():
    """Manually extract hidden data from QR code (with password)."""
    try:
        # Validate request
        qr_image = request.files.get('image')
        password = request.form.get('password', '').strip() or None
        
        if not qr_image:
            return jsonify({'error': 'QR code image is required'}), 400
        
        validate_image(qr_image)
        
        # Save image temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        qr_filename = secure_filename(qr_image.filename)
        qr_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{qr_filename}")
        qr_image.save(qr_path)
        
        try:
            # Extract both public and secret data
            public_data, secret_data = extract_from_qr_stego(qr_path, password)
            
            logger.info(f"Successfully extracted from QR code")
            return jsonify({
                'success': True,
                'publicData': public_data,
                'secretData': secret_data
            }), 200
        finally:
            # Clean up
            if os.path.exists(qr_path):
                os.remove(qr_path)
    
    except ValueError as e:
        logger.error(f"QR extraction error: {str(e)}")
        safe_error = sanitize_error(str(e), current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 400
    except Exception as e:
        logger.error(f"Error extracting from QR code: {str(e)}")
        safe_error = sanitize_error('An error occurred while extracting data', current_app.config['DEBUG'])
        return jsonify({'error': safe_error}), 500


@api.route('/qr/capacity', methods=['POST'])
def calculate_qr_capacity():
    """Calculate steganography capacity for a QR code."""
    try:
        public_data = request.form.get('public_data', '')
        scale = int(request.form.get('scale', 15))
        
        capacity = qr_stego.calculate_qr_capacity(public_data, scale)
        
        return jsonify({
            'totalCapacityBytes': capacity_bytes,
            'totalCapacityFormatted': format_bytes(capacity_bytes)
        }), 200
    
    except Exception as e:
        return jsonify({'error': sanitize_error(str(e))}), 400


@api.route('/qr/detect', methods=['POST'])
def detect_qr():
    """Quick QR detection endpoint for camera scanner - just checks if QR exists.
    
    This endpoint is called frequently by the camera scanner (every 500ms),
    so it's designed to be fast and return consistent responses even on errors.
    """
    filepath = None
    try:
        # Validate image file is present
        if 'image' not in request.files:
            logger.debug('QR detection: No image in request')
            return jsonify({'detected': False}), 200
        
        image_file = request.files['image']
        
        if not image_file or image_file.filename == '':
            logger.debug('QR detection: Empty image file')
            return jsonify({'detected': False}), 200
        
        # Calculate MD5 hash for deduplication
        image_data = image_file.read()
        image_hash = hashlib.md5(image_data).hexdigest()
        current_time = time.time()
        
        # Clean up expired cache entries (older than 5 seconds)
        expired_keys = [k for k, v in qr_detection_cache.items() if current_time - v[0] > 5]
        for k in expired_keys:
            del qr_detection_cache[k]
            logger.debug(f'QR detection: Cleaned up expired cache entry {k[:8]}...')
        
        # Check cache for recent identical request (within 1 second)
        if image_hash in qr_detection_cache:
            cache_timestamp, cached_response = qr_detection_cache[image_hash]
            if current_time - cache_timestamp < 1.0:
                logger.debug(f'QR detection: Cache hit for hash {image_hash[:8]}...')
                return jsonify(cached_response), 200
        
        # Reset file pointer after reading for hash
        image_file.seek(0)
        
        # Create upload folder if it doesn't exist
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        # Save temporarily with unique filename
        filename = f"detect_{uuid.uuid4().hex}.png"
        filepath = os.path.join(upload_folder, filename)
        
        try:
            image_file.save(filepath)
            logger.debug(f'QR detection: Saved temp file {filename}')
        except Exception as save_error:
            logger.error(f'QR detection: Failed to save image - {str(save_error)}')
            return jsonify({'detected': False}), 200
        
        # Try to decode QR code
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            from PIL import Image
            
            # Open and decode the image
            img = Image.open(filepath)
            decoded_objects = pyzbar_decode(img)
            detected = len(decoded_objects) > 0
            
            if detected:
                logger.info(f'QR detection: QR code detected in frame')
            else:
                logger.debug('QR detection: No QR code in frame')
            
            # Cache the response
            response_data = {'detected': detected, 'success': True}
            qr_detection_cache[image_hash] = (current_time, response_data)
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
        
    finally:
        # Always clean up temporary file
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
                logger.debug(f'QR detection: Cleaned up temp file')
            except Exception as cleanup_error:
                logger.warning(f'QR detection: Failed to clean up {filepath} - {str(cleanup_error)}')


@api.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    max_size = current_app.config.get('MAX_CONTENT_LENGTH', 64 * 1024 * 1024)
    max_size_mb = max_size // (1024 * 1024)
    return jsonify({
        'error': f'Request too large. Maximum total size is {max_size_mb} MB. '
                 f'Individual limits: Images (10 MB), Files (50 MB)'
    }), 413

