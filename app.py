from flask import Flask, request, render_template, send_file
from PIL import Image
import os
from cryptography.fernet import Fernet
import logging

# Configuration
UPLOAD_FOLDER = 'uploads/'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit to 16 MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Generate a key for encryption
key = Fernet.generate_key()
cipher = Fernet(key)

# Logging configuration
logging.basicConfig(filename='app.log', level=logging.INFO)

# Encryption function (for sensitive data)
def encrypt_data(data):
    return cipher.encrypt(data)

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data)

def validate_file(file_path):
    if not os.path.isfile(file_path):
        raise ValueError("Invalid file path.")
    if not file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.apk', '.zip', '.rar')):
        raise ValueError("Unsupported image format.")

# Function to hide file in image
def hide_file_in_image(image_path, file_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())
    total_pixels = len(pixels)

    # File data to hide
    original_file_name = os.path.basename(file_path).encode('utf-8')
    data_to_hide = len(original_file_name).to_bytes(4, 'big') + original_file_name

    with open(file_path, 'rb') as f:
        file_data = f.read()
        data_to_hide += len(file_data).to_bytes(4, 'big') + file_data

    # Check image capacity
    if len(data_to_hide) * 8 > total_pixels:
        raise ValueError("Image does not have enough pixels to store this data.")

    # Hide data in pixels
    for i in range(len(data_to_hide)):
        byte = data_to_hide[i]
        for bit in range(8):
            pixel = list(pixels[i * 8 + bit])
            pixel[0] = (pixel[0] & 0xFE) | ((byte >> (7 - bit)) & 1)
            pixels[i * 8 + bit] = tuple(pixel)

    img.putdata(pixels)
    output_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'output_image.png')
    img.save(output_image_path)
    return output_image_path

# Function to extract file from image
def extract_file_from_image(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())

    # Extract hidden bits
    hidden_bits = []
    for pixel in pixels:
        hidden_bits.append(pixel[0] & 1)

    # Convert bits to bytes
    hidden_data = bytearray()
    for i in range(0, len(hidden_bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | hidden_bits[i + j]
        hidden_data.append(byte)

    # Decode file name length, name, and file data length
    original_file_name_length = int.from_bytes(hidden_data[:4], 'big')
    original_file_name = hidden_data[4:4 + original_file_name_length].decode('utf-8')
    data_length_start = 4 + original_file_name_length
    data_length = int.from_bytes(hidden_data[data_length_start:data_length_start + 4], 'big')

    # Extract hidden file data
    hidden_data = hidden_data[data_length_start + 4:data_length_start + 4 + data_length]
    extracted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_file_name)
    with open(extracted_file_path, 'wb') as f:
        f.write(hidden_data)

    return extracted_file_path

# Clean up temporary files
def cleanup_files(*file_paths):
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    logging.info("File upload initiated.")
    try:
        image = request.files['image']
        file_to_hide = request.files['file']

        # Validate file types
        if not image or not file_to_hide:
            raise ValueError("Both image and file to hide must be provided.")

        # Save uploaded files
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_hide.filename)
        image.save(image_path)
        file_to_hide.save(file_path)

        output_image_path = hide_file_in_image(image_path, file_path)
        return render_template('result.html', image_path=output_image_path)
    except ValueError as e:
        logging.error("Error occurred: %s", str(e))
        return render_template('error.html', error_message=str(e)), 400
    except Exception as e:
        logging.error("Error occurred: %s", str(e))
        return render_template('error.html', error_message="An unexpected error occurred."), 500
    finally:
        cleanup_files(image_path, file_path)  # Clean up uploaded files

@app.route('/extract', methods=['POST'])
def extract_file():
    try:
        image = request.files['image']
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(image_path)

        extracted_file_path = extract_file_from_image(image_path)
        return send_file(extracted_file_path, as_attachment=True)
    except Exception as e:
        logging.error("Error occurred: %s", str(e))
        return render_template('error.html', error_message="An unexpected error occurred."), 500
    finally:
        cleanup_files(image_path)  # Clean up uploaded files

if __name__ == '__main__':
    app.run(debug=True)
