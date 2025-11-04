"""File validation utilities."""
from werkzeug.datastructures import FileStorage


ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
ALLOWED_FILE_EXTENSIONS = {'txt', 'pdf', 'mp4', 'apk', 'zip', 'jpg', 'png', 'doc', 'docx', 'xlsx'}


def validate_file(file: FileStorage, allowed_extensions: set) -> None:
    """
    Validate uploaded file.
    
    Args:
        file: The uploaded file
        allowed_extensions: Set of allowed file extensions
        
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


def validate_image(file: FileStorage) -> None:
    """Validate that file is an allowed image type."""
    validate_file(file, ALLOWED_IMAGE_EXTENSIONS)


def validate_hideable_file(file: FileStorage) -> None:
    """Validate that file can be hidden in an image."""
    validate_file(file, ALLOWED_FILE_EXTENSIONS)
