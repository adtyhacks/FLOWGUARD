"""Authentication middleware and token lifecycle helpers."""

from datetime import datetime, timedelta, timezone
from functools import wraps
import uuid
from flask import g, jsonify, request
from sqlalchemy.orm import Session
from ..models import User, UserToken


def create_user_token(session: Session, user_id: int, lifetime_seconds: int = 7200) -> UserToken:
    """Generate a cryptographic UUID token and persist it in the database."""
    token_str = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=lifetime_seconds)
    
    token = UserToken(
        token=token_str,
        user_id=user_id,
        created_at=now,
        expires_at=expires_at,
        is_revoked=False,
    )
    session.add(token)
    session.commit()
    return token


def revoke_user_token(session: Session, token_str: str) -> bool:
    """Revoke a token in the database upon logout."""
    token = session.query(UserToken).filter_by(token=token_str).first()
    if token:
        token.is_revoked = True
        session.commit()
        return True
    return False


def require_auth(f):
    """Decorator to enforce UUID token authentication on route handlers.
    
    Validates token presence, active status, and expiration against the mode's database.
    Populates g.current_user and g.current_token.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = (request.headers.get("Authorization") or "").strip()
        if not auth_header:
            return jsonify({
                "error": "Unauthorized",
                "message": "Missing Authorization header. Expected 'Bearer <token>'"
            }), 401
            
        parts = auth_header.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "error": "Unauthorized",
                "message": "Malformed Authorization header. Expected format: 'Bearer <token>'"
            }), 401
            
        token_str = parts[1].strip()
        if not token_str:
            return jsonify({
                "error": "Unauthorized",
                "message": "Empty authentication token provided"
            }), 401
            
        db = getattr(g, "db", None)
        if db is None:
            return jsonify({
                "error": "Internal Server Error",
                "message": "Database session unavailable"
            }), 500
            
        token = db.query(UserToken).filter_by(token=token_str).first()
        if not token:
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid authentication token"
            }), 401
            
        if not token.is_valid():
            return jsonify({
                "error": "Unauthorized",
                "message": "Authentication token has expired or been revoked"
            }), 401
            
        # Token is valid; populate Flask context
        g.current_user = token.user
        g.current_token = token
        return f(*args, **kwargs)
        
    return decorated_function
