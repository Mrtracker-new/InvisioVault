"""API routes for steganography operations."""
from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
import os
import secrets
from io import BytesIO
import logging

from utils.steganography import hide_file_in_image, extract_file_from_image
from utils.polyglot import create_polyglot, extract_from_polyglot
from utils.validators import validate_image, validate_hideable_file


api = Blueprint('api', __name__, url_prefix='/api')
logger = logging.getLogger(__name__)


@api.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'message': 'InvisioVault API is running'}), 200


@api.route('/hide', methods=['POST'])
def hide_file():
    """Hide a file in an image."""
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
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error hiding file: {str(e)}")
        return jsonify({'error': 'An error occurred while hiding the file'}), 500


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
        return jsonify({'error': 'An error occurred while downloading the file'}), 500


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
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error extracting file: {str(e)}")
        return jsonify({'error': 'An error occurred while extracting the file'}), 500


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
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating polyglot: {str(e)}")
        return jsonify({'error': 'An error occurred while creating the polyglot file'}), 500


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
        return jsonify({'error': 'An error occurred while downloading the file'}), 500


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
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error extracting from polyglot: {str(e)}")
        return jsonify({'error': 'An error occurred while extracting the file'}), 500


@api.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    return jsonify({'error': 'File too large. Maximum size is 64 MB'}), 413
