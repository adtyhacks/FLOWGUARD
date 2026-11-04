"""Synthetic user registration and authentication endpoints."""

from flask import Blueprint, g, jsonify, request
from sqlalchemy.exc import IntegrityError
from ..auth.middleware import create_user_token, require_auth, revoke_user_token
from ..models import User


def register_auth_endpoints(bp: Blueprint) -> None:
    """Register auth routes on the provided blueprint (vuln or sec)."""
    
    @bp.route("/auth/register", methods=["POST"])
    def register():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                "error": "Bad Request",
                "message": "Invalid JSON payload. Expected a JSON object."
            }), 400
            
        raw_username = data.get("username")
        raw_email = data.get("email")
        raw_password = data.get("password")
        
        if not isinstance(raw_username, str) or not isinstance(raw_email, str) or not isinstance(raw_password, str):
            return jsonify({
                "error": "Bad Request",
                "message": "Fields 'username', 'email', and 'password' must be non-empty strings."
            }), 400
            
        username = raw_username.strip()
        email = raw_email.strip().lower()
        password = raw_password
        
        if not username or not email or not password:
            return jsonify({
                "error": "Bad Request",
                "message": "Missing required fields: username, email, and password must not be empty."
            }), 400
            
        if len(password) < 6:
            return jsonify({
                "error": "Bad Request",
                "message": "Password must be at least 6 characters long."
            }), 400
            
        db = g.db
        # Check existing user
        existing_user = db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            return jsonify({
                "error": "Conflict",
                "message": "User with this username or email already exists."
            }), 409
            
        try:
            user = User(username=username, email=email)
            user.set_password(password)
            db.add(user)
            db.commit()
            return jsonify({
                "message": "User registered successfully",
                "user": user.to_dict()
            }), 201
        except IntegrityError:
            db.rollback()
            return jsonify({
                "error": "Conflict",
                "message": "A user with the given username or email already exists."
            }), 409
        except Exception as e:
            db.rollback()
            return jsonify({
                "error": "Internal Server Error",
                "message": "Failed to register user."
            }), 500

    @bp.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({
                "error": "Bad Request",
                "message": "Invalid JSON payload. Expected a JSON object."
            }), 400
            
        raw_username = data.get("username")
        raw_password = data.get("password")
        
        if not isinstance(raw_username, str) or not isinstance(raw_password, str):
            return jsonify({
                "error": "Bad Request",
                "message": "Fields 'username' and 'password' must be non-empty strings."
            }), 400
            
        username = raw_username.strip()
        password = raw_password
        
        if not username or not password:
            return jsonify({
                "error": "Bad Request",
                "message": "Username and password are required and cannot be empty."
            }), 400
            
        db = g.db
        user = db.query(User).filter(
            (User.username == username) | (User.email == username.lower())
        ).first()
        
        if not user or not user.check_password(password):
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid username or password."
            }), 401
            
        # Generate UUID session token
        token = create_user_token(db, user.id)
        
        return jsonify({
            "message": "Authentication successful",
            "token": token.token,
            "user": user.to_dict(),
            "expires_at": token.expires_at.isoformat()
        }), 200

    @bp.route("/auth/logout", methods=["POST"])
    @require_auth
    def logout():
        db = g.db
        if g.current_token:
            if not revoke_user_token(db, g.current_token.token):
                return jsonify({
                    "error": "Internal Server Error",
                    "message": "Failed to invalidate authentication token."
                }), 500
        return jsonify({
            "message": "Successfully logged out"
        }), 200

    @bp.route("/auth/me", methods=["GET"])
    @require_auth
    def get_profile():
        return jsonify({
            "user": g.current_user.to_dict()
        }), 200
