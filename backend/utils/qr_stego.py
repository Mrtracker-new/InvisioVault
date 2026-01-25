"""QR Code steganography utilities for generating customized QR codes with hidden data."""
import segno
from PIL import Image
import io
import os
from typing import Optional, Tuple
from pyzbar.pyzbar import decode as pyzbar_decode
import tempfile

from utils.steganography import hide_file_in_image, extract_file_from_image


def generate_qr_with_stego(
    public_data: str,
    secret_text: str,
    output_path: str,
    password: Optional[str] = None,
    fg_color: str = "#000000",
    bg_color: str = "#FFFFFF",
    scale: int = 20,  # Increased to 20 for better readability
    logo_path: Optional[str] = None
) -> str:
    """
    Generate a QR code with hidden secret text using URL fragment encoding.
    
    IMPORTANT: The QR code data contains the public URL + a fragment (#) with the encrypted secret.
    Normal scanners open the URL and ignore the fragment.
    InvisioVault parses the full QR data including the fragment to extract the secret.
    This is robust against camera capture and recompression (unlike LSB steganography).
    
    Args:
        public_data: The visible QR code data (URL, text, vCard, etc.)
        secret_text: The hidden text message to embed
        output_path: Path where the final QR code will be saved
        password: Optional password for encrypting the hidden data
        fg_color: Foreground color in hex format (default: black)
        bg_color: Background color in hex format (default: white)
        scale: QR code size multiplier (default: 20)
        logo_path: Optional path to logo image to embed in center
        
    Returns:
        Path to the generated QR code image
        
    Raises:
        ValueError: If QR generation fails
    """
    try:
        import base64
        import logging
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import os as os_module
        
        logger = logging.getLogger(__name__)
        
        # Encrypt the secret text if password is provided
        if password:
            logger.info("Encrypting secret with password...")
            # Generate salt
            salt = os_module.urandom(16)
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            
            # Encrypt secret
            iv = os_module.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad secret text to block size
            secret_bytes = secret_text.encode('utf-8')
            padding_length = 16 - (len(secret_bytes) % 16)
            padded_secret = secret_bytes + bytes([padding_length] * padding_length)
            
            encrypted = encryptor.update(padded_secret) + encryptor.finalize()
            
            # Combine salt + iv + encrypted data
            secret_payload = salt + iv + encrypted
        else:
            # No password - just encode the secret
            secret_payload = secret_text.encode('utf-8')
        
        # Encode secret as base64
        secret_encoded = base64.b64encode(secret_payload).decode('ascii')
        logger.info(f"Secret encoded to {len(secret_encoded)} base64 characters")
        
        # Combine public data and secret using URL fragment
        # Normal QR scanners will open the URL and ignore everything after #
        # InvisioVault will parse the full data
        combined_qr_data = f"{public_data}#IVDATA:{secret_encoded}"
        logger.info(f"Combined QR data length: {len(combined_qr_data)} characters")
        
        # Generate QR code with the combined data
        qr = segno.make(combined_qr_data, error='h')
        
        # Create temp file
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_qr:
            temp_qr_path = temp_qr.name
        
        # Save QR code with custom colors and scale
        qr.save(
            temp_qr_path,
            scale=scale,
            dark=fg_color,
            light=bg_color,
            border=2
        )
        logger.info(f"QR code saved to temp file: {temp_qr_path}")
        
        # If logo is provided, embed it
        if logo_path:
            logger.info(f"Embedding logo from: {logo_path}")
            temp_qr_path = _embed_logo_in_qr(temp_qr_path, logo_path)
        
        # Convert to proper RGB PNG
        qr_image = Image.open(temp_qr_path).convert('RGB')
        qr_image.save(output_path, 'PNG', optimize=False, compress_level=0)
        logger.info(f"Final QR code saved to: {output_path}")
        
        # Clean up
        if os.path.exists(temp_qr_path):
            os.remove(temp_qr_path)
        
        return output_path
    
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to generate QR code: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to generate QR code: {str(e)}")


def _embed_logo_in_qr(qr_path: str, logo_path: str) -> str:
    """
    Embed a logo image in the center of a QR code.
    
    Args:
        qr_path: Path to the QR code image
        logo_path: Path to the logo image
        
    Returns:
        Path to the QR code with embedded logo (overwrites original)
    """
    # Open QR code and logo
    qr_img = Image.open(qr_path).convert('RGBA')
    logo_img = Image.open(logo_path).convert('RGBA')
    
    # Calculate logo size (max 20% of QR code size to maintain scannability)
    qr_width, qr_height = qr_img.size
    logo_max_size = int(min(qr_width, qr_height) * 0.2)
    
    # Resize logo while maintaining aspect ratio
    logo_img.thumbnail((logo_max_size, logo_max_size), Image.Resampling.LANCZOS)
    
    # Calculate position to center the logo
    logo_width, logo_height = logo_img.size
    logo_pos = (
        (qr_width - logo_width) // 2,
        (qr_height - logo_height) // 2
    )
    
    # Create a white background for the logo to ensure contrast
    background = Image.new('RGBA', logo_img.size, 'WHITE')
    background.paste(logo_img, (0, 0), logo_img)
    
    # Paste logo onto QR code
    qr_img.paste(background, logo_pos, background)
    
    # Convert back to RGB and save
    qr_rgb = qr_img.convert('RGB')
    qr_rgb.save(qr_path, 'PNG')
    
    return qr_path


def extract_from_qr_stego(
    qr_path: str,
    password: Optional[str] = None
) -> Tuple[str, str]:
    """
    Extract both visible QR data and hidden secret text from a QR code.
    
    The QR code data contains the public URL + a fragment (#IVDATA:) with the encrypted secret.
    Normal scanners see only the URL part.
    InvisioVault parses the fragment to extract the secret.
    
    Args:
        qr_path: Path to the QR code image
        password: Optional password if the hidden data is encrypted
        
    Returns:
        Tuple of (public_qr_data, secret_text)
        
    Raises:
        ValueError: If extraction fails
    """
    try:
        import base64
        import logging
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        logger = logging.getLogger(__name__)
        
        # Decode QR code data
        logger.info(f"Extracting from QR code: {qr_path}")
        decoded_objects = pyzbar_decode(Image.open(qr_path))
        
        if not decoded_objects:
            raise ValueError("No QR code found in the image")
        
        # Get the full QR data
        qr_data = decoded_objects[0].data.decode('utf-8', errors='replace')
        logger.info(f"Full QR data: {qr_data[:100]}...")
        
        # Check for fragment-based format (#IVDATA:)
        if '#IVDATA:' in qr_data:
            parts = qr_data.split('#IVDATA:')
            public_data = parts[0]
            secret_encoded = parts[1] if len(parts) > 1 else ""
            logger.info(f"Found IVDATA fragment. Public data: {public_data}, Secret length: {len(secret_encoded)}")
            
            if secret_encoded:
                try:
                    # Decode standard base64
                    secret_payload = base64.b64decode(secret_encoded)
                    logger.info(f"Decoded secret payload: {len(secret_payload)} bytes")
                    
                    # Check if it's encrypted (has salt + iv + data)
                    if password:
                        if len(secret_payload) < 32:  # salt(16) + iv(16)
                            raise ValueError("Invalid encrypted data format")
                        
                        logger.info("Decrypting with password...")
                        # Extract salt (16 bytes) and IV (16 bytes)
                        salt = secret_payload[:16]
                        iv = secret_payload[16:32]
                        encrypted_data = secret_payload[32:]
                        
                        # Derive key from password
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                            backend=default_backend()
                        )
                        key = kdf.derive(password.encode('utf-8'))
                        
                        # Decrypt
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
                        
                        # Remove padding
                        padding_length = decrypted_padded[-1]
                        secret_text = decrypted_padded[:-padding_length].decode('utf-8')
                        logger.info(f"Successfully decrypted secret: {len(secret_text)} characters")
                    else:
                        # No password - check if data is encrypted
                        if len(secret_payload) >= 32:
                            # Data looks encrypted but no password provided
                            logger.warning("Data appears encrypted but no password provided")
                            raise ValueError("This QR code is password protected")
                        # Data is plain text
                        secret_text = secret_payload.decode('utf-8')
                        logger.info(f"Decoded plain text secret: {len(secret_text)} characters")
                    
                except base64.binascii.Error:
                    logger.error("Failed to decode base64 data")
                    raise ValueError("Failed to decode hidden data")
                except ValueError as e:
                    if "password" in str(e).lower():
                        raise
                    logger.error(f"Decryption error: {str(e)}")
                    raise ValueError(f"Failed to decrypt hidden data: {str(e)}")
            else:
                secret_text = ""
        else:
            # Regular QR code without hidden data
            logger.info("No IVDATA fragment found - regular QR code")
            public_data = qr_data
            secret_text = ""
        
        logger.info(f"Extraction complete. Public: {len(public_data)} chars, Secret: {len(secret_text)} chars")
        return public_data, secret_text
    
    except ValueError:
        raise
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to extract data from QR code: {str(e)}", exc_info=True)
        raise ValueError(f"Failed to extract data from QR code: {str(e)}")


def calculate_qr_capacity(
    public_data: str,
    scale: int = 10
) -> int:
    """
    Calculate the steganography capacity of a QR code based on its size.
    
    Args:
        public_data: The public QR data (determines QR code complexity)
        scale: QR code size multiplier
        
    Returns:
        Estimated capacity in bytes for steganographic data
    """
    try:
        # Generate temporary QR to measure size
        qr = segno.make(public_data, error='h')
        
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            qr.save(temp_path, scale=scale, border=2)
            
            # Open image and calculate capacity
            img = Image.open(temp_path).convert('RGB')
            total_pixels = len(list(img.getdata()))
            
            # Capacity: 3 bits per pixel (1 per RGB channel) / 8 = bytes
            # Subtract overhead for metadata (~100 bytes)
            capacity_bytes = (total_pixels * 3) // 8 - 100
            
            return max(0, capacity_bytes)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
    
    except Exception:
        # Default estimate if calculation fails
        return 90000  # ~90KB for typical QR code


def decode_qr_only(qr_path: str) -> str:
    """
    Decode only the visible QR code data without extracting steganography.
    
    Args:
        qr_path: Path to the QR code image
        
    Returns:
        The visible QR code data as a string
        
    Raises:
        ValueError: If no QR code is found
    """
    try:
        decoded_objects = pyzbar_decode(Image.open(qr_path))
        
        if not decoded_objects:
            raise ValueError("No QR code found in the image")
        
        return decoded_objects[0].data.decode('utf-8')
    
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Failed to decode QR code: {str(e)}")
