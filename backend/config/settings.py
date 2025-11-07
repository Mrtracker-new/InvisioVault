"""Application configuration."""
import os
import secrets
import logging
from pathlib import Path
from urllib.parse import urlparse


class Config:
    """Base configuration."""
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    @classmethod
    def validate_secret_key(cls):
        """Validate that SECRET_KEY is properly set."""
        if not cls.SECRET_KEY:
            raise ValueError(
                "SECRET_KEY environment variable is not set! "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
    
    @classmethod
    def validate_cors_origins(cls, origins):
        """Validate CORS origins to prevent security issues."""
        logger = logging.getLogger(__name__)
        
        if not origins:
            raise ValueError("CORS_ORIGINS cannot be empty!")
        
        for origin in origins:
            origin = origin.strip()
            
            # Block wildcard
            if origin == '*':
                raise ValueError(
                    "Wildcard CORS origin '*' is not allowed! "
                    "Specify exact domains instead."
                )
            
            # Validate URL format
            if origin and not origin.startswith(('http://', 'https://')):
                raise ValueError(
                    f"Invalid CORS origin '{origin}'. "
                    f"Must start with http:// or https://"
                )
            
            # Parse and validate
            try:
                parsed = urlparse(origin)
                if not parsed.netloc:
                    raise ValueError(f"Invalid CORS origin '{origin}': missing domain")
            except Exception as e:
                raise ValueError(f"Invalid CORS origin '{origin}': {e}")
            
            # Warn about localhost in production
            if not cls.DEBUG and 'localhost' in origin:
                logger.warning(
                    f"WARNING: CORS origin '{origin}' contains 'localhost' in production mode!"
                )
        
        return [o.strip() for o in origins]
    
    # Upload settings
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp/uploads')
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB
    
    # CORS settings - will be set by subclasses
    _cors_origins_raw = None
    CORS_ORIGINS = []  # Will be set after validation
    
    # Logging
    LOG_FILE = os.getenv('LOG_FILE', '/tmp/app.log')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    @staticmethod
    def init_app(app):
        """Initialize application configuration."""
        # Ensure upload folder exists
        Path(Config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
        
        # Validate and set CORS origins
        # Read from environment variable OR use class default
        cors_raw = os.getenv('CORS_ORIGINS') or app.config.get('_cors_origins_raw')
        
        if not cors_raw:
            raise ValueError("CORS_ORIGINS must be set! Either via environment variable or config class.")
        
        cors_list = cors_raw.split(',')
        app.config['CORS_ORIGINS'] = Config.validate_cors_origins(cors_list)
        
        # Validate critical security settings in production
        if not app.config['DEBUG']:
            Config.validate_secret_key()


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    UPLOAD_FOLDER = 'uploads'
    
    # Default CORS for local development
    _cors_origins_raw = 'http://localhost:5173,http://localhost:3000'
    
    # Auto-generate secret key for development if not set
    if not Config.SECRET_KEY:
        SECRET_KEY = secrets.token_hex(32)
        print(f"⚠️  WARNING: Using auto-generated SECRET_KEY for development")
        print(f"⚠️  Set SECRET_KEY in .env for production!")


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    
    # Production MUST have SECRET_KEY set - no fallback!
    # Validation happens in init_app()
    
    # Production should use your actual domains
    # Example: Set CORS_ORIGINS env var to: https://invisio-vault.vercel.app,https://yourdomain.com
    # Fallback to Vercel deployment if not set
    _cors_origins_raw = 'https://invisio-vault.vercel.app'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
