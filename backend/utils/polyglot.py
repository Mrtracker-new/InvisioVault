"""Polyglot file utilities for hiding files within other files."""
import zipfile
import os
import tempfile
import shutil
from typing import Tuple
try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False


def create_polyglot(carrier_path: str, file_to_hide_path: str, output_path: str, password: str = None) -> str:
    """
    Create a TRUE polyglot file that works as both the carrier format AND a ZIP file.
    The trick: ZIP files read from the end, so we can prepend any data before the ZIP structure.
    
    Args:
        carrier_path: Path to the carrier file (any format)
        file_to_hide_path: Path to the file to hide
        output_path: Path where the polyglot file will be saved
        password: Optional password for the zip archive
        
    Returns:
        Path to the output polyglot file
        
    Note:
        The output file can be:
        - Opened with the carrier's native application (image viewer, PDF reader, etc.)
        - Renamed to .zip and extracted like a normal ZIP file
        - Both work because ZIP readers start from the end of the file!
    """
    # Get the original filename
    original_filename = os.path.basename(file_to_hide_path)
    
    # Create a temporary zip file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip:
        temp_zip_path = temp_zip.name
    
    try:
        # First, read the carrier file data
        with open(carrier_path, 'rb') as carrier:
            carrier_data = carrier.read()
        carrier_size = len(carrier_data)
        
        # Create zip archive with the file
        if password and HAS_PYZIPPER:
            # Use pyzipper for password-protected ZIP (AES encryption)
            with pyzipper.AESZipFile(temp_zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode())
                zf.write(file_to_hide_path, original_filename)
        else:
            # Use standard zipfile (no password support)
            with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Store the filename in the archive
                zf.write(file_to_hide_path, original_filename)
        
        # Read the ZIP data
        with open(temp_zip_path, 'rb') as zf:
            zip_data = zf.read()
        
        # Now write the polyglot file:
        # 1. Carrier data first (this makes it work as carrier format)
        # 2. ZIP data after (this makes it work as ZIP when reading from end)
        with open(output_path, 'wb') as output:
            output.write(carrier_data)
            output.write(zip_data)
        
        # Fix ZIP offsets to account for prepended carrier data
        # ZIP files store offsets to each file entry, we need to add carrier_size to each
        _fix_zip_offsets(output_path, carrier_size)
        
        return output_path
        
    finally:
        # Clean up temporary zip file
        if os.path.exists(temp_zip_path):
            os.remove(temp_zip_path)


def _fix_zip_offsets(file_path: str, offset: int):
    """
    Fix ZIP file offsets in a polyglot file.
    This adjusts the central directory to account for prepended carrier data.
    """
    with open(file_path, 'r+b') as f:
        data = f.read()
        
        # Find End of Central Directory (EOCD) signature
        eocd_sig = b'\x50\x4b\x05\x06'
        eocd_pos = data.rfind(eocd_sig)
        
        if eocd_pos == -1:
            return  # Not a valid ZIP
        
        # Read offset to central directory from EOCD (at position +16 from signature)
        cd_offset_pos = eocd_pos + 16
        old_cd_offset = int.from_bytes(data[cd_offset_pos:cd_offset_pos + 4], 'little')
        
        # Calculate new offset (add carrier size)
        new_cd_offset = old_cd_offset + offset
        
        # Write new offset back
        f.seek(cd_offset_pos)
        f.write(new_cd_offset.to_bytes(4, 'little'))
        
        # Now fix each file entry's local header offset in central directory
        cd_pos = new_cd_offset
        f.seek(cd_pos)
        
        while True:
            f.seek(cd_pos)
            sig = f.read(4)
            
            # Check for Central Directory File Header signature
            if sig != b'\x50\x4b\x01\x02':
                break
            
            # Read local header offset (at position +42 from CD entry start)
            f.seek(cd_pos + 42)
            old_local_offset = int.from_bytes(f.read(4), 'little')
            new_local_offset = old_local_offset + offset
            
            # Write new offset
            f.seek(cd_pos + 42)
            f.write(new_local_offset.to_bytes(4, 'little'))
            
            # Move to next entry (need to read lengths to calculate size)
            f.seek(cd_pos + 28)
            name_len = int.from_bytes(f.read(2), 'little')
            extra_len = int.from_bytes(f.read(2), 'little')
            comment_len = int.from_bytes(f.read(2), 'little')
            
            # CD entry size: 46 bytes + name + extra + comment
            cd_pos += 46 + name_len + extra_len + comment_len


def extract_from_polyglot(polyglot_path: str, password: str = None) -> Tuple[bytes, str]:
    """
    Extract the hidden file from a polyglot file.
    
    Args:
        polyglot_path: Path to the polyglot file
        password: Optional password for encrypted ZIP
        
    Returns:
        Tuple of (file_data, original_filename)
        
    Raises:
        ValueError: If extraction fails or no hidden file found
    """
    try:
        # Read the entire polyglot file
        with open(polyglot_path, 'rb') as f:
            data = f.read()
        
        # Look for ZIP signature (PK\x03\x04 or PK\x05\x06 for empty archives)
        # We look for the central directory end signature which is at the end
        zip_signature = b'PK\x03\x04'
        
        # Find the first occurrence of ZIP signature
        zip_start = data.find(zip_signature)
        
        if zip_start == -1:
            raise ValueError("No hidden file found in the polyglot")
        
        # Extract the ZIP portion
        zip_data = data[zip_start:]
        
        # Create a temporary file to write the zip data
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip:
            temp_zip.write(zip_data)
            temp_zip_path = temp_zip.name
        
        try:
            # Try to open with pyzipper first (supports AES encryption)
            if HAS_PYZIPPER and password:
                try:
                    with pyzipper.AESZipFile(temp_zip_path, 'r') as zf:
                        zf.setpassword(password.encode())
                        filenames = zf.namelist()
                        if not filenames:
                            raise ValueError("ZIP archive is empty")
                        first_file = filenames[0]
                        file_data = zf.read(first_file)
                        return file_data, first_file
                except RuntimeError as e:
                    if 'Bad password' in str(e):
                        raise ValueError("Incorrect password")
                    raise
            
            # Fallback to standard zipfile
            with zipfile.ZipFile(temp_zip_path, 'r') as zf:
                # Get the first file in the archive
                filenames = zf.namelist()
                if not filenames:
                    raise ValueError("ZIP archive is empty")
                
                first_file = filenames[0]
                
                # Check if file is encrypted
                info = zf.getinfo(first_file)
                if info.flag_bits & 0x1:  # File is encrypted
                    if not password:
                        raise ValueError("This file is password-protected. Please provide the password.")
                    try:
                        file_data = zf.read(first_file, pwd=password.encode())
                    except RuntimeError:
                        raise ValueError("Incorrect password")
                else:
                    file_data = zf.read(first_file)
                
                return file_data, first_file
                
        finally:
            # Clean up temp zip file
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
                
    except Exception as e:
        raise ValueError(f"Failed to extract from polyglot: {str(e)}")
