"""Flask application factory for ShopZone e-commerce laboratory."""

from flask import Flask, g, jsonify, request
from .blueprints import admin_bp, products_bp, sec_bp, vuln_bp
from .config import Config, validate_admin_key
from .db import close_all_sessions, get_session_factory, init_db


def create_app(config_class=None, init_database: bool = True) -> Flask:
    """Create and configure the ShopZone Flask application."""
    app = Flask(__name__)
    
    # 1. Configuration & fail-fast ADMIN_KEY validation
    cfg = config_class or Config
    app.config.from_object(cfg)
    
    # Explicitly re-validate admin key
    validate_admin_key(app.config.get("ADMIN_KEY"))
    
    # 2. Register blueprints (support both short /vuln/api, /sec/api and full /vulnerable/api, /secure/api)
    app.register_blueprint(admin_bp)
    app.register_blueprint(products_bp, url_prefix="/api")
    app.register_blueprint(vuln_bp)
    app.register_blueprint(sec_bp)
    app.register_blueprint(vuln_bp, name="vulnerable_full", url_prefix="/vulnerable/api")
    app.register_blueprint(sec_bp, name="secure_full", url_prefix="/secure/api")
    
    # 3. Explicit per-request database session management
    @app.before_request
    def bind_database_session():
        """Bind the appropriate database session (vulnerable vs secure) to Flask g."""
        path = request.path
        if path.startswith("/vuln/") or path.startswith("/vulnerable/"):
            mode = "vulnerable"
        elif path.startswith("/sec/") or path.startswith("/secure/"):
            mode = "secure"
        else:
            # Mode-neutral routes (e.g. /api/products, /api/admin) default to secure db
            mode = "secure"
            
        session_factory = get_session_factory(mode, app.config)
        g.db = session_factory()
        g.db_mode = mode

    @app.teardown_request
    def cleanup_database_session(exception=None):
        """Close the per-request database session."""
        db = getattr(g, "db", None)
        if db is not None:
            db.close()

    @app.teardown_appcontext
    def cleanup_scoped_factories(exception=None):
        """Remove thread-local scoped sessions on context teardown."""
        close_all_sessions()
        
    # 4. Global JSON error handlers
    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({
            "error": "Not Found",
            "message": "The requested resource or endpoint was not found."
        }), 404

    @app.errorhandler(500)
    def handle_server_error(e):
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unhandled server exception occurred."
        }), 500

    @app.route("/", methods=["GET"])
    def index():
        return jsonify({
            "service": "ShopZone E-Commerce Laboratory",
            "status": "online",
            "modes": {
                "vulnerable": "/vuln/api",
                "secure": "/sec/api",
            },
            "catalog": "/api/products",
            "admin": "/api/admin",
        }), 200

    # 5. Initialize databases if requested
    if init_database:
        with app.app_context():
            init_db(mode="all", config=app.config, seed=True)

    return app
