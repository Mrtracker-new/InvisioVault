"""Steganography utilities for hiding and extracting files in images."""
from PIL import Image
import zlib
import mimetypes
import os


def hide_file_in_image(image_path: str, file_path: str, output_path: str) -> str:
    """
    Hide a file in an image using LSB steganography with compression.
    
    Args:
        image_path: Path to the host image
        file_path: Path to the file to hide
        output_path: Path where the output image will be saved
        
    Returns:
        Path to the output image
        
    Raises:
        ValueError: If the image doesn't have enough capacity
    """
    # Open the host image
    host_img = Image.open(image_path).convert("RGB")
    host_pixels = list(host_img.getdata())
    total_pixels = len(host_pixels)

    # Read and compress the file
    with open(file_path, 'rb') as f:
        file_data = f.read()
    compressed_data = zlib.compress(file_data, level=9)

    # Prepare metadata
    original_filename = os.path.basename(file_path)
    
    # Better MIME type detection
    mime_type = mimetypes.guess_type(file_path)[0]
    if not mime_type:
        # Fallback based on file extension
        ext = os.path.splitext(file_path)[1].lower()
        mime_map = {
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.bmp': 'image/bmp',
            '.webp': 'image/webp',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.zip': 'application/zip',
            '.mp4': 'video/mp4'
        }
        mime_type = mime_map.get(ext, 'application/octet-stream')
    
    metadata = f"{original_filename}|{mime_type}".encode('utf-8')
    metadata_length = len(metadata).to_bytes(2, 'big')

    # Combine metadata and compressed data
    data_to_hide = metadata_length + metadata + compressed_data

    # Check image capacity
    if len(data_to_hide) * 8 > total_pixels * 3:
        raise ValueError("Host image does not have enough capacity to store the data.")

    # Embed data into the image using LSB
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
    host_img.putdata(host_pixels)
    host_img.save(output_path, 'PNG')
    return output_path


def extract_file_from_image(image_path: str) -> tuple[bytes, str, str]:
    """
    Extract a hidden file from an image.
    
    Args:
        image_path: Path to the image containing hidden data
        
    Returns:
        Tuple of (file_data, original_filename, mime_type)
        
    Raises:
        ValueError: If extraction fails
    """
    # Open the image
    img = Image.open(image_path)
    pixels = list(img.getdata())

    # Extract binary data from LSB
    data_bits = []
    for pixel in pixels:
        for channel in pixel[:3]:  # Only use RGB channels
            data_bits.append(channel & 1)
    
    # Convert bits to bytes
    data_bytes = bytearray()
    for i in range(0, len(data_bits), 8):
        byte = 0
        for bit in data_bits[i:i + 8]:
            byte = (byte << 1) | bit
        data_bytes.append(byte)

    try:
        # Parse metadata length and metadata
        metadata_length = int.from_bytes(data_bytes[:2], 'big')
        metadata = data_bytes[2:2 + metadata_length].decode('utf-8')
        original_filename, mime_type = metadata.split('|')

        # Extract and decompress data
        compressed_data = bytes(data_bytes[2 + metadata_length:])
        decompressed_data = zlib.decompress(compressed_data)

        return decompressed_data, original_filename, mime_type
    except Exception as e:
        raise ValueError(f"Failed to extract file: {str(e)}")
