"""Flask application factory for InvisioVault API."""
from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os
import atexit

from config.settings import config
from api.routes import api
from utils.cleanup import init_cleanup_scheduler, stop_cleanup_scheduler


def create_app(config_name='default'):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)  # This validates and sets CORS_ORIGINS
    
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
    
    # Setup logging
    logging.basicConfig(
        level=getattr(logging, app.config['LOG_LEVEL']),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(app.config['LOG_FILE']),
            logging.StreamHandler()
        ]
    )
    
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
