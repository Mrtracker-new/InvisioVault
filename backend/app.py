"""Flask application factory for InvisioVault API."""
from flask import Flask, request
from flask_cors import CORS
import logging
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from config.settings import config
from api.routes import api
from extensions import limiter   # shared Limiter instance (no app yet)
# NOTE: init_cleanup_scheduler is NOT imported here.
# Production: started by gunicorn.conf.py post_fork hook (once per worker, after fork).
# Development: started in the __main__ block below.
# Starting it inside create_app() is WRONG under --preload: the thread would
# be born in the master process and killed by os.fork() before the worker runs.


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
    
    # ---------------------------------------------------------------------------
    # Rate limiting
    # ---------------------------------------------------------------------------
    # All configuration (default_limits, storage_uri, strategy, headers_enabled)
    # and all per-route decorators (@limiter.limit, @limiter.exempt) are declared
    # in extensions.py and routes.py respectively.  flask-limiter 3.x requires
    # all constructor options to be passed to Limiter() — init_app() only accepts
    # the Flask app object.
    #
    # endpoint summary:
    #   /api/health : @limiter.exempt  (routes.py)
    #   /qr/detect  : @limiter.limit("60 per minute")  (routes.py)
    #   /           : @limiter.exempt  (below, after blueprint registration)
    #   all others  : global 200/day + 100/hour  (extensions.py Limiter ctor)
    limiter.init_app(app)

    
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
        
        # Permissions-Policy is intentionally NOT set on API responses.
        # This header is a document-level directive: setting it on REST API
        # responses causes Chrome to merge it with the parent document's policy,
        # which can silently restrict browser features (including getUserMedia /
        # camera access) even when camera=() is not explicitly listed.
        # Feature policy for the frontend document is set in vercel.json and
        # index.html — those are the only correct places for this header.
        
        # HSTS - Force HTTPS (only in production with HTTPS)
        if not app.config['DEBUG'] and request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response
    
    # Register blueprints — must happen AFTER limiter.init_app() so that the
    # per-route limits already attached as decorators in routes.py are correctly
    # wired to the app's request lifecycle.
    app.register_blueprint(api)

    # Root probe — Render (and any monitoring system) occasionally hits / to
    # confirm the server is alive.  Exempt it from rate limiting so it can
    # never return a 429.  The decorator form is used (not the post-registration
    # limiter.exempt(fn) call) because the limiter instance is already bound to
    # `app` at this point and the route is registered on `app` directly (not a
    # blueprint), so no endpoint-name ambiguity arises.
    @app.route('/')
    @limiter.exempt
    def _root_probe():
        """Root health probe — always responds 200, exempt from rate limiting."""
        return {
            'name': 'InvisioVault API',
            'status': 'running',
            'version': '2.0.1'
        }

    app.logger.info(
        "Rate-limit active — per-route limits and exemptions declared in routes.py:"
        " /qr/detect=60/min, /api/health=exempt, /=exempt"
    )


    # Return clean JSON on rate-limit breach so clients (including the camera
    # scanner) can handle 429s gracefully instead of receiving an HTML error page.
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        from flask import make_response, jsonify
        resp = make_response(jsonify({
            'error': 'Too many requests. Please slow down.',
            'retry_after': getattr(e, 'description', 'unknown')
        }), 429)
        # Standard header so HTTP clients know when to retry
        resp.headers['Retry-After'] = '60'
        return resp

    # Create upload folder (safe even if it already exists)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # NOTE: FileCleanupScheduler is NOT started here.
    # See module docstring at the top of this file for the rationale.

    return app


# ---------------------------------------------------------------------------
# WSGI entry point
# ---------------------------------------------------------------------------
# Gunicorn imports this module and uses the `app` name as the WSGI callable.
# With --preload (set in gunicorn.conf.py) this runs once in the master process
# before any workers are forked.  create_app() must therefore be free of
# process-level side effects such as starting threads — those belong in the
# gunicorn.conf.py post_fork hook.
env = os.getenv('FLASK_ENV', 'development')
app = create_app(env)


if __name__ == '__main__':
    # Development server path — Flask's built-in server, no gunicorn.
    # We start the scheduler here because there is no post_fork hook.
    from utils.cleanup import init_cleanup_scheduler, stop_cleanup_scheduler
    import atexit

    upload_folder   = app.config['UPLOAD_FOLDER']
    max_age_hours   = int(os.getenv('FILE_MAX_AGE_HOURS',        '1'))
    interval_mins   = int(os.getenv('CLEANUP_INTERVAL_MINUTES', '10'))
    init_cleanup_scheduler(upload_folder, max_age_hours, interval_mins)
    atexit.register(stop_cleanup_scheduler)  # Clean shutdown for dev server only

    port = int(os.getenv('PORT', 5000))
    app.logger.info("========================================")
    app.logger.info("InvisioVault Backend — Development Server")
    app.logger.info(f"Environment : {env}")
    app.logger.info(f"Port        : {port}")
    app.logger.info(f"Debug Mode  : {app.config['DEBUG']}")
    app.logger.info("========================================")
    app.run(
        host='0.0.0.0',
        port=port,
        debug=app.config['DEBUG'],
    )
