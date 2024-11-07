from flask import Flask, request, render_template, send_file
from PIL import Image
import os
import logging

# Configuration
UPLOAD_FOLDER = 'uploads/'
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit for uploads

# Create uploads folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Logging configuration
logging.basicConfig(filename='app.log', level=logging.INFO)

# File type validation
def validate_file(file):
    if file is None or file.filename == '':
        raise ValueError("No file uploaded.")
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif', '.apk', '.zip', '.rar')):
        raise ValueError("Unsupported file format.")

# Function to hide file in image
def hide_file_in_image(image_path, file_path):
    # Open the host image
    host_img = Image.open(image_path).convert("RGB")
    host_pixels = list(host_img.getdata())
    total_pixels = len(host_pixels)

    # Read the file to hide
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Prepare the data to hide: store file length and file data
    data_to_hide = len(file_data).to_bytes(4, 'big') + file_data

    # Check image capacity
    if len(data_to_hide) * 8 > total_pixels * 3:  # Each pixel can store 3 bits
        raise ValueError("Host image does not have enough capacity to store this data.")

    # Embed data in pixels
    data_index = 0
    bit_index = 0
    for pixel_index in range(total_pixels):
        pixel = list(host_pixels[pixel_index])
        for channel_index in range(3):
            if data_index < len(data_to_hide):
                byte = data_to_hide[data_index]
                pixel[channel_index] = (pixel[channel_index] & ~1) | ((byte >> (7 - bit_index)) & 1)
                bit_index += 1
                if bit_index == 8:
                    bit_index = 0
                    data_index += 1
        host_pixels[pixel_index] = tuple(pixel)

    # Save the modified image
    host_img.putdata(host_pixels)
    output_image_path = os.path.join(os.path.dirname(image_path), 'output_image.png')
    host_img.save(output_image_path)
    return output_image_path

# Function to extract file from image
def extract_file_from_image(image_path):
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    # Extract bits for hidden data
    hidden_data_bits = []
    for pixel in pixels:
        for channel in pixel:
            hidden_data_bits.append(channel & 1)

    # Convert bits to bytes
    hidden_data = bytearray()
    for i in range(0, len(hidden_data_bits), 8):
        byte = 0
        for bit in hidden_data_bits[i:i+8]:
            byte = (byte << 1) | bit
        hidden_data.append(byte)

    # Read the data length
    data_length = int.from_bytes(hidden_data[:4], 'big')
    hidden_file_data = hidden_data[4:4 + data_length]

    # Save extracted file
    extracted_file_path = os.path.join(os.path.dirname(image_path), 'extracted_file')
    with open(extracted_file_path, 'wb') as f:
        f.write(hidden_file_data)

    return extracted_file_path

# Clean up temporary files
def cleanup_files(*file_paths):
    for file_path in file_paths:
        if file_path and os.path.exists(file_path):  # Check if file_path is not None
            os.remove(file_path)

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/upload', methods=['POST'])
def upload_file():
    logging.info("File upload initiated.")
    image_path = None
    file_path = None  # Initialize file_path to None
    try:
        image = request.files.get('image')
        file_to_hide = request.files.get('file')

        if not image or not file_to_hide:
            raise ValueError("Both image and file to hide must be provided.")
        
        # Validate file formats
        validate_file(image)  # Corrected to use the image directly
        
        # Save uploaded files
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_hide.filename)
        image.save(image_path)
        file_to_hide.save(file_path)

        # Hide the file in the image
        output_image_path = hide_file_in_image(image_path, file_path)
        return render_template('result.html', image_path=output_image_path)
    
    except ValueError as e:
        logging.error("Validation error: %s", str(e))
        return render_template('error.html', error_message=str(e)), 400
    except Exception as e:
        logging.error("Unexpected error occurred: %s", str(e))
        return render_template('error.html', error_message="An unexpected error occurred."), 500
    finally:
        cleanup_files(image_path, file_path)  # This will now work even if file_path is None

@app.route('/extract', methods=['POST'])
def extract_file():
    logging.info("File extraction initiated.")
    image_path = None
    try:
        image = request.files.get('image')

        if not image:
            raise ValueError("An image file must be provided.")

        # Validate file format
        validate_file(image.filename, ['.png', '.jpg', '.jpeg'])

        # Save uploaded image
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(image_path)

        # Extract hidden file
        extracted_file_path = extract_file_from_image(image_path)
        return send_file(extracted_file_path, as_attachment=True)
    
    except ValueError as e:
        logging.error("Validation error: %s", str(e))
        return render_template('error.html', error_message=str(e)), 400
    except Exception as e:
        logging.error("Unexpected error occurred: %s", str(e))
        return render_template('error.html', error_message="An unexpected error occurred."), 500
    finally:
        cleanup_files(image_path)

if __name__ == '__main__':
    app.run(debug=True)
