# InvisioVault
This is a Flask-based web application for file steganography, where users can hide a file within an image or extract a hidden file from an image. By embedding file data into the least significant bits of an image, this application provides a secure and easy-to-use platform for hiding and retrieving files within images.

# Image File Steganography Web Application

This project is a Flask-based web application that enables users to hide files within images and extract hidden files from images. It uses the least significant bit (LSB) technique to embed file data into the pixels of a host image.

## Features

- **File Hiding**: Upload an image and a file to hide, and the app will embed the file within the image using the LSB method.
- **File Extraction**: Upload an image with a hidden file, and the app will extract and download the embedded file.
- **File Validation**: Ensures valid image and file formats for both upload and extraction operations.
- **Error Handling**: Provides user-friendly error messages for invalid formats, large files, or unexpected errors.
- **Logging**: Logs upload and extraction attempts for debugging purposes.

## Requirements

- Python 3.x
- Flask
- PIL (Pillow library)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Mrtracker-new/image-steganography.git
    cd image-steganography
    ```

2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3. Run the application:
    ```bash
    python app.py
    ```

4. Visit `http://127.0.0.1:5000` in your browser to use the application.

## Usage

1. **Hide File in Image**:
   - Go to the homepage.
   - Upload an image (PNG, JPEG, BMP) and a file to hide (supports common formats).
   - Click "Upload" to generate an image with the hidden file.
   
2. **Extract File from Image**:
   - Go to the "Extract" page.
   - Upload an image that contains hidden data.
   - The hidden file will be extracted and made available for download.

## Folder Structure

- `uploads/` - Stores the uploaded and processed files.
- `templates/` - Contains HTML templates for the application.
- `app.log` - Log file for tracking errors and user activity.

## Security Considerations

- Maximum file size for uploads is set to 16MB to prevent large files from overloading the server.
- Supported file types for hiding are validated for security.
- Cleanup function deletes temporary files after processing to optimize storage and security.

## License

This project is licensed under the MIT License.
