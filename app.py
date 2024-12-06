from flask import Flask, request, render_template, send_file, make_response, g
from PIL import Image
import os
import logging
import zlib
import secrets
from io import BytesIO
import mimetypes

# Configuration
UPLOAD_FOLDER = 'uploads/'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024  # 64 MB limit for uploads

# Create uploads folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Logging configuration
logging.basicConfig(filename='app.log', level=logging.INFO)


# Helper function to validate file type
def validate_file(file, allowed_extensions):
    if not file:
        raise ValueError("No file provided.")
    if '.' not in file.filename or file.filename.split('.')[-1].lower() not in allowed_extensions:
        raise ValueError(f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}")


# Hide file in image
def hide_file_in_image(image_path, file_path):
    """Hide a file in an image, including its metadata."""
    # Open the host image
    host_img = Image.open(image_path).convert("RGB")
    host_pixels = list(host_img.getdata())
    total_pixels = len(host_pixels)

    # Read the file to hide and compress it
    with open(file_path, 'rb') as f:
        file_data = f.read()
    compressed_data = zlib.compress(file_data)

    # Get original filename and MIME type
    original_filename = os.path.basename(file_path)
    mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'

    # Prepare metadata
    metadata = f"{original_filename}|{mime_type}".encode('utf-8')
    metadata_length = len(metadata).to_bytes(2, 'big')  # Store metadata length as 2 bytes

    # Combine metadata and compressed data
    data_to_hide = metadata_length + metadata + compressed_data

    # Check image capacity
    if len(data_to_hide) * 8 > total_pixels * 3:
        raise ValueError("Host image does not have enough capacity to store the data.")

    # Embed data into the image
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
    output_path = os.path.join(app.config['UPLOAD_FOLDER'], 'output_image.png')
    host_img.putdata(host_pixels)
    host_img.save(output_path)
    return output_path




# Extract file from image
def extract_file_from_image(image_path):
    """Extract a hidden file from an image, including its metadata."""
    # Open the image
    img = Image.open(image_path)
    pixels = list(img.getdata())

    # Extract binary data
    data_bits = []
    for pixel in pixels:
        for channel in pixel:
            data_bits.append(channel & 1)
    data_bytes = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = 0
        for bit in data_bits[i:i + 8]:
            byte = (byte << 1) | bit
        data_bytes.append(byte)

    # Parse metadata length and metadata
    metadata_length = int.from_bytes(data_bytes[:2], 'big')
    metadata = data_bytes[2:2 + metadata_length].decode('utf-8')
    original_filename, mime_type = metadata.split('|')

    # Extract compressed data
    compressed_data = bytes(data_bytes[2 + metadata_length:])
    decompressed_data = zlib.decompress(compressed_data)

    # Return extracted file data and metadata
    return decompressed_data, original_filename, mime_type



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        image = request.files.get('image')
        file_to_hide = request.files.get('file')

        # Validate files
        validate_file(image, ['png', 'jpg', 'jpeg', 'bmp'])
        validate_file(file_to_hide, ['txt', 'pdf', 'mp4', 'apk', 'zip'])

        # Save files
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_hide.filename)
        image.save(image_path)
        file_to_hide.save(file_path)

        # Hide file in the image
        output_image_path = hide_file_in_image(image_path, file_path)

        return render_template('result.html', image_path=output_image_path)

    except Exception as e:
        logging.error(f"Error during upload: {e}")
        return render_template('error.html', error_message=str(e))
    
@app.route('/assets')
def download_hidden_file():
      # Generate a random filename using secrets module
    filename = secrets.token_urlsafe(16)
    
    # Assuming the hidden file is stored in the 'uploads' folder
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'output_image.png')
    
    # Rename the file to the random filename
    os.rename(file_path, os.path.join(app.config['UPLOAD_FOLDER'], f'{filename}.png'))
    
    # Send the file with the random filename
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], f'{filename}.png'), as_attachment=True)



@app.route('/extract', methods=['POST'])
def extract_file():
    try:
        image = request.files.get('image')
        validate_file(image, ['png', 'jpg', 'jpeg', 'bmp'])

        # Save image
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(image_path)

        # Extract file from image
        file_data, original_filename, mime_type = extract_file_from_image(image_path)

        # Send extracted file
        output = BytesIO(file_data)
        output.seek(0)
        return send_file(
            output,
            as_attachment=True,
            download_name=original_filename,
            mimetype=mime_type
        )

    except Exception as e:
        logging.error(f"Error during extraction: {e}")
        return render_template('error.html', error_message=str(e))


if __name__ == '__main__':
    app.run(debug=True)
