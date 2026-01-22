"""File validation utilities."""
from werkzeug.datastructures import FileStorage


# File size limits (in bytes)
MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 MB - for carrier images
MAX_HIDEABLE_FILE_SIZE = 50 * 1024 * 1024  # 50 MB - for files to hide

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
ALLOWED_FILE_EXTENSIONS = {'txt', 'pdf', 'mp4', 'apk', 'zip', 'jpg', 'png', 'doc', 'docx', 'xlsx'}


def validate_file(file: FileStorage, allowed_extensions: set, max_size: int = None) -> None:
    """
    Validate uploaded file.
    
    Args:
        file: The uploaded file
        allowed_extensions: Set of allowed file extensions
        max_size: Maximum file size in bytes (optional)
        
    Raises:
        ValueError: If validation fails
    """
    if not file:
        raise ValueError("No file provided.")
    
    if not file.filename:
        raise ValueError("File has no name.")
    
    if '.' not in file.filename:
        raise ValueError("File has no extension.")
    
    extension = file.filename.rsplit('.', 1)[1].lower()
    if extension not in allowed_extensions:
        raise ValueError(
            f"Unsupported file type '.{extension}'. "
            f"Allowed: {', '.join(sorted(allowed_extensions))}"
        )
    
    # Progressive size validation to prevent memory exhaustion
    if max_size:
        # First check: Use Content-Length header if available
        if file.content_length and file.content_length > max_size:
            raise ValueError(
                f"File too large. Maximum size is {max_size // (1024*1024)} MB"
            )
        
        # Second check: Determine actual file size by seeking to end
        # This is necessary as content_length may not always be present
        try:
            current_pos = file.stream.tell()
            file.stream.seek(0, 2)  # Seek to end
            size = file.stream.tell()
            file.stream.seek(current_pos)  # Reset to original position
            
            if size > max_size:
                size_mb = size / (1024 * 1024)
                max_mb = max_size / (1024 * 1024)
                raise ValueError(
                    f"File size ({size_mb:.1f} MB) exceeds maximum of {max_mb:.0f} MB"
                )
        except (OSError, IOError) as e:
            # If we can't determine size, log warning but allow validation to continue
            # Flask's MAX_CONTENT_LENGTH will still protect us
            pass


def validate_image(file: FileStorage) -> None:
    """Validate that file is an allowed image type with size limit."""
    validate_file(file, ALLOWED_IMAGE_EXTENSIONS, MAX_IMAGE_SIZE)


def validate_hideable_file(file: FileStorage) -> None:
    """Validate that file can be hidden in an image with size limit."""
    validate_file(file, ALLOWED_FILE_EXTENSIONS, MAX_HIDEABLE_FILE_SIZE)
