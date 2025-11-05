"""Flask application factory for InvisioVault API."""
from flask import Flask
from flask_cors import CORS
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
    config[config_name].init_app(app)
    
    # Setup CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"],
            "expose_headers": ["Content-Disposition"]
        }
    })
    
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
            'version': '2.0.0',
            'status': 'running'
        }
    
    return app


if __name__ == '__main__':
    env = os.getenv('FLASK_ENV', 'development')
    app = create_app(env)
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=app.config['DEBUG']
    )
