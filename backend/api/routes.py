"""API routes for steganography operations."""
from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
import os
import secrets
from io import BytesIO
import logging

from utils.steganography import hide_file_in_image, extract_file_from_image
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

        if not image or not file_to_hide:
            return jsonify({'error': 'Both image and file are required'}), 400

        # Validate files
        validate_image(image)
        validate_hideable_file(file_to_hide)

        # Save files temporarily
        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        image_filename = secure_filename(image.filename)
        file_filename = secure_filename(file_to_hide.filename)
        
        image_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{image_filename}")
        file_path = os.path.join(upload_folder, f"{secrets.token_hex(8)}_{file_filename}")
        
        image.save(image_path)
        file_to_hide.save(file_path)

        # Hide file in image
        output_filename = f"{secrets.token_urlsafe(16)}.png"
        output_path = os.path.join(upload_folder, output_filename)
        hide_file_in_image(image_path, file_path, output_path)

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
        file_data, original_filename, mime_type = extract_file_from_image(image_path)

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


@api.errorhandler(413)
def request_entity_too_large(error):
    """Handle file too large error."""
    return jsonify({'error': 'File too large. Maximum size is 64 MB'}), 413
