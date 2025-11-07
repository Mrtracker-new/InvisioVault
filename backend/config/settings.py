"""Application configuration."""
import os
import secrets
from pathlib import Path


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
    
    # Upload settings
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/tmp/uploads')
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB
    
    # CORS settings
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5173,http://localhost:3000').split(',')
    
    # Logging
    LOG_FILE = os.getenv('LOG_FILE', '/tmp/app.log')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    @staticmethod
    def init_app(app):
        """Initialize application configuration."""
        # Ensure upload folder exists
        Path(Config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
        
        # Validate critical security settings in production
        if not app.config['DEBUG']:
            Config.validate_secret_key()


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    UPLOAD_FOLDER = 'uploads'
    
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


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
