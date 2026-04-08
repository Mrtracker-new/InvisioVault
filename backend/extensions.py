"""Shared Flask extension instances for InvisioVault.

This module holds extension objects created *without* a bound Flask application
(the standard "application factory" pattern).  Import ``limiter`` from here
instead of creating new Limiter() instances in app.py or routes.py.

Rationale
---------
flask-limiter maps a rate-limit to the correct endpoint at *decoration time* —
i.e. when ``@limiter.limit(...)`` is evaluated on the view function.  Inside a
Blueprint the endpoint name is ``"api.<view_name>"``.  If the Limiter instance
were created inside ``create_app()`` it would not yet exist when ``routes.py``
is imported, causing a circular import.  The solution is a dedicated
``extensions.py`` that holds the Limiter instance created *before* the app:

    # extensions.py  (this file)
    limiter = Limiter(key_func=..., default_limits=[...], ...)   # no app arg

    # routes.py
    from extensions import limiter
    @api.route('/qr/detect', methods=['POST'])
    @limiter.limit("60 per minute")               # ← applied before register_blueprint()
    def detect_qr(): ...

    # app.py  (create_app factory)
    from extensions import limiter
    limiter.init_app(app)                         # bind to the Flask instance

All configuration options that would normally be passed to ``Limiter(app=app,
...)`` must instead be passed here to the constructor, because
``Limiter.init_app(app)`` only accepts the ``app`` argument (flask-limiter 3.x
design).  Runtime overrides are still possible via Flask config keys
(``RATELIMIT_*``).
"""

import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ---------------------------------------------------------------------------
# Shared Limiter instance
# ---------------------------------------------------------------------------
# All per-route decorator usage (``@limiter.limit``, ``@limiter.exempt``) in
# routes.py imports this object.  ``limiter.init_app(app)`` is called later
# inside ``create_app()`` in app.py.
#
# Configuration:
#   default_limits : Global cap — 200/day + 100/hour per IP.
#                    Camera scanner and other polling is further constrained by
#                    per-route decorators in routes.py (60/min for /qr/detect).
#   storage_uri    : Prefer Redis in production; fall back to in-process memory.
#                    NOTE: memory:// is not shared across gunicorn workers, so
#                    counters reset per-worker.  Redis URL should be set via
#                    the REDIS_URL environment variable on Render.
#   strategy       : fixed-window — simplest and lowest overhead.
#   headers_enabled: Expose X-RateLimit-* headers so clients can self-throttle.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "100 per hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),
    strategy="fixed-window",
    headers_enabled=True,
)
