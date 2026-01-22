"""Flask application factory for InvisioVault API."""
from flask import Flask, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os
import atexit
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from config.settings import config
from api.routes import api
from utils.cleanup import init_cleanup_scheduler, stop_cleanup_scheduler


def create_app(config_name='default'):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)  # This validates and sets CORS_ORIGINS
    
    # Apply MAX_CONTENT_LENGTH to Flask app (enables automatic request size validation)
    app.config['MAX_CONTENT_LENGTH'] = config[config_name].MAX_CONTENT_LENGTH
    
    # Setup CORS (AFTER config initialization so CORS_ORIGINS is validated)
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
            "expose_headers": ["Content-Disposition"],
            "supports_credentials": False
        }
    })
    
    # Log CORS origins for debugging
    app.logger.info(f"CORS enabled for origins: {app.config['CORS_ORIGINS']}")
    
    # Setup rate limiting to prevent abuse and DOS attacks
    # Global limits: 200 requests per day, 50 per hour per IP
    # Heavy operations (hide/create): 10 per hour
    # Light operations (extract): 20 per hour
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.getenv('REDIS_URL', 'memory://'),
        strategy="fixed-window",
        headers_enabled=True  # Add rate limit headers to responses
    )
    
    # Store limiter in app for use in routes
    app.limiter = limiter
    
    # Request size validation middleware
    @app.before_request
    def validate_request_size():
        """Validate request content length before processing to prevent DoS attacks."""
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_length = request.content_length
            max_length = app.config.get('MAX_CONTENT_LENGTH')
            
            if content_length and max_length and content_length > max_length:
                from flask import jsonify
                return jsonify({
                    'error': f'Request too large. Maximum size is {max_length // (1024*1024)} MB'
                }), 413
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, app.config['LOG_LEVEL']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(app.config['LOG_FILE']),
            logging.StreamHandler()
        ]
    )
    
    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response):
        """Add security headers to prevent common attacks."""
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Prevent clickjacking attacks
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Enable XSS protection (legacy browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy - don't leak URLs to third parties
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy - prevent XSS and data injection
        csp = (
            "default-src 'none'; "
            "script-src 'none'; "
            "style-src 'none'; "
            "img-src 'none'; "
            "font-src 'none'; "
            "connect-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'none'"
        )
        response.headers['Content-Security-Policy'] = csp
        
        # Permissions Policy - restrict browser features
        response.headers['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=(), '
            'payment=(), usb=(), magnetometer=(), gyroscope=()'
        )
        
        # HSTS - Force HTTPS (only in production with HTTPS)
        if not app.config['DEBUG'] and request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response
    
    # Register blueprints
    app.register_blueprint(api)
    
    # Create upload folder
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize file cleanup scheduler
    # Runs every 10 minutes, deletes files older than 1 hour
    max_age_hours = int(os.getenv('FILE_MAX_AGE_HOURS', '1'))
    cleanup_interval = int(os.getenv('CLEANUP_INTERVAL_MINUTES', '10'))
    init_cleanup_scheduler(app.config['UPLOAD_FOLDER'], max_age_hours, cleanup_interval)
    
    # Ensure cleanup stops when app shuts down
    atexit.register(stop_cleanup_scheduler)
    
    @app.route('/')
    def index():
        return {
            'name': 'InvisioVault API',
            'version': '2.0.1',
            'status': 'running',
            'cors_origins': app.config.get('CORS_ORIGINS', []),
            'flask_env': os.getenv('FLASK_ENV', 'not_set'),
            'debug': app.config['DEBUG']
        }
    
    return app


# Create app instance for gunicorn
env = os.getenv('FLASK_ENV', 'development')
app = create_app(env)


if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=app.config['DEBUG']
    )
