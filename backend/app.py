"""Flask application factory for InvisioVault API."""
from flask import Flask
from flask_cors import CORS
import logging
import os

from config.settings import config
from api.routes import api


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
