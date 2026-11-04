"""Synthetic user lifecycle and in-memory session management for FLOWGUARD."""

from __future__ import annotations

import secrets
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .client import FlowGuardClient
from .config import FlowGuardConfig


def _validated_token_expiry(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Invalid token expiry.") from exc
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Token expiry must be a timezone-aware datetime.")
    expires_at = value.astimezone(timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise ValueError("Token expiry must be in the future.")
    return expires_at


class SyntheticUser:
    """In-memory representation of a synthetic ShopZone user."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        token: str | None = None,
        user_id: int | None = None,
        _default_mode: str = "secure",
        _mode_tokens: dict[str, str] | None = None,
        _mode_expiries: dict[str, datetime | None] | None = None,
    ) -> None:
        self.username = username
        self.email = email
        self.password = password
        self.token = token
        self.user_id = user_id
        self._default_mode = _default_mode
        self._mode_tokens = dict(_mode_tokens or {})
        self._mode_expiries = dict(_mode_expiries or {})
        if self.token:
            self._mode_tokens[self._default_mode] = self.token

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "email": self.email,
            "password": "***REDACTED***" if self.password else None,
            "token": "***REDACTED***" if self._mode_tokens else None,
            "user_id": self.user_id,
        }

    def __repr__(self) -> str:
        """Never print credentials or bearer tokens in logs or evidence."""
        return (
            f"SyntheticUser(username={self.username!r}, email={self.email!r}, "
            f"user_id={self.user_id}, token={'***REDACTED***' if self._mode_tokens else None})"
        )

    def _active_token(self, mode: str) -> str | None:
        token = self._mode_tokens.get(mode)
        expires_at = self._mode_expiries.get(mode)
        try:
            if not isinstance(token, str) or str(uuid.UUID(token)) != token:
                raise ValueError("Invalid UUID token.")
            expires_at = _validated_token_expiry(expires_at)
        except (ValueError, AttributeError, TypeError):
            self.clear_token(mode)
            return None
        self._mode_expiries[mode] = expires_at
        return token

    def set_token(self, mode: str, token: str, expires_at: datetime | str | None) -> None:
        selected_mode = mode.lower()
        self.clear_token(selected_mode)
        if not isinstance(token, str):
            raise ValueError("Token must be a valid UUID string.")
        try:
            canonical_token = str(uuid.UUID(token))
        except (ValueError, AttributeError) as exc:
            raise ValueError("Token must be a valid UUID string.") from exc
        if canonical_token != token:
            raise ValueError("Token must be a canonical UUID string.")
        validated_expiry = _validated_token_expiry(expires_at)
        self._mode_tokens[selected_mode] = canonical_token
        self._mode_expiries[selected_mode] = validated_expiry
        if selected_mode == self._default_mode:
            self.token = canonical_token

    def clear_token(self, mode: str) -> None:
        selected_mode = mode.lower()
        self._mode_tokens.pop(selected_mode, None)
        self._mode_expiries.pop(selected_mode, None)
        if selected_mode == self._default_mode:
            self.token = None

    def auth_headers(self, mode: str | None = None) -> dict[str, str]:
        """Return Bearer headers when a valid token is present."""
        selected_mode = (mode or self._default_mode).lower()
        token = self._active_token(selected_mode)
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}


class AuthSession:
    """A single synthetic-user authenticated session object."""

    user: SyntheticUser
    authentication_headers: dict[str, str]
    session_metadata: dict[str, Any]
    _authenticated: bool = field(default=False, repr=False)

    def __init__(
        self,
        user: SyntheticUser,
        authenticated: bool = False,
        authentication_headers: dict[str, str] | None = None,
        session_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.user = user
        self.authentication_headers = dict(authentication_headers or {})
        self.session_metadata = dict(session_metadata or {})
        self._authenticated = bool(authenticated and self._headers_match_user_token())
        if not self._authenticated:
            self.authentication_headers.clear()

    def _headers_match_user_token(self) -> bool:
        mode = self.session_metadata.get("mode")
        if not isinstance(mode, str):
            return False
        expected_headers = self.user.auth_headers(mode)
        return bool(expected_headers) and self.authentication_headers == expected_headers

    def to_dict(self) -> dict[str, Any]:
        from .redaction import sanitize_value

        mode = self.session_metadata.get("mode")
        is_authenticated = self._authenticated and isinstance(mode, str) and bool(self.user.auth_headers(mode))
        return sanitize_value({
            "user": self.user.to_dict(),
            "authenticated": is_authenticated,
            "authentication_headers": self.authentication_headers,
            "session_metadata": self.session_metadata,
        })

    @property
    def authenticated(self) -> bool:
        if self._authenticated and not self._headers_match_user_token():
            self._authenticated = False
            self.authentication_headers.clear()
        return self._authenticated

    @authenticated.setter
    def authenticated(self, value: bool) -> None:
        self._authenticated = bool(value)

    def __repr__(self) -> str:
        """Avoid exposing credentials or bearer tokens in logs or evidence."""
        is_authenticated = self._authenticated and self._headers_match_user_token()
        return (
            f"AuthSession(username={self.user.username!r}, authenticated={is_authenticated}, "
            f"headers={'***REDACTED***' if self.authentication_headers else {}})"
        )


class SyntheticUserManager:
    """Create, authenticate, and manage synthetic ShopZone users via HTTP."""

    def __init__(self, client: FlowGuardClient | None = None, *, mode: str = "secure") -> None:
        self.mode = mode.lower()
        self.client = client or FlowGuardClient(FlowGuardConfig(target_mode=self.mode))
        self._users: dict[str, SyntheticUser] = {}
        self._sessions: dict[tuple[str, str], AuthSession] = {}

    def _selected_mode(self, mode: str | None) -> str:
        selected_mode = (mode or self.mode).lower()
        if selected_mode not in {"vulnerable", "secure"}:
            raise ValueError("mode must be either 'vulnerable' or 'secure'.")
        return selected_mode

    @staticmethod
    def _validate_password(password: str) -> None:
        if not isinstance(password, str) or len(password) < 6:
            raise ValueError("password must be a string of at least 6 characters.")

    @staticmethod
    def _parse_expiry(value: Any) -> datetime | None:
        return _validated_token_expiry(value)

    def _invalidate_session(self, username: str, mode: str) -> None:
        session = self._sessions.get((username, mode))
        if session is not None:
            session.authenticated = False
            session.authentication_headers.clear()

    def generate_username(self, prefix: str = "flowguard_user") -> str:
        """Generate a unique synthetic username."""
        while True:
            candidate = f"{prefix}_{secrets.token_hex(16)}"
            if candidate not in self._users:
                return candidate

    def generate_email(self, username: str | None = None) -> str:
        """Generate a unique synthetic email address using the lab domain."""
        candidate = username or self.generate_username("synthetic")
        email = f"{candidate}@flowguard.local"
        existing_emails = {user.email.lower() for user in self._users.values()}
        while email.lower() in existing_emails:
            email = f"{candidate}_{secrets.token_hex(8)}@flowguard.local"
        return email

    def generate_password(self, length: int = 18) -> str:
        """Generate a strong random password with mixed character classes."""
        if not isinstance(length, int) or isinstance(length, bool) or not 12 <= length <= 256:
            raise ValueError("Generated password length must be between 12 and 256 characters.")
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-="
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            if (
                any(ch.islower() for ch in password)
                and any(ch.isupper() for ch in password)
                and any(ch.isdigit() for ch in password)
                and any(ch in "!@#$%^&*_-=" for ch in password)
            ):
                return password

    def create_user(self, username: str | None = None, email: str | None = None, password: str | None = None) -> SyntheticUser:
        """Create an in-memory synthetic user record without performing registration."""
        resolved_username = self.generate_username() if username is None else username
        if not isinstance(resolved_username, str) or not resolved_username.strip():
            raise ValueError("username must be a non-empty string.")
        resolved_username = resolved_username.strip()
        resolved_email = self.generate_email(resolved_username) if email is None else email
        if not isinstance(resolved_email, str) or not resolved_email.strip():
            raise ValueError("email must be a non-empty string.")
        resolved_email = resolved_email.strip().lower()
        resolved_password = self.generate_password() if password is None else password
        self._validate_password(resolved_password)
        if resolved_username in self._users:
            raise ValueError("A synthetic user with this username already exists.")
        if any(user.email.lower() == resolved_email for user in self._users.values()):
            raise ValueError("A synthetic user with this email already exists.")
        user = SyntheticUser(
            username=resolved_username,
            email=resolved_email,
            password=resolved_password,
            _default_mode=self.mode,
        )
        self._users[resolved_username] = user
        return user

    def list_users(self) -> list[SyntheticUser]:
        """Return the current in-memory synthetic users."""
        return list(self._users.values())

    def get_session(self, username: str, *, mode: str | None = None) -> AuthSession | None:
        """Return the active auth session for a username, if one exists."""
        return self._sessions.get((username, self._selected_mode(mode)))

    def get_auth_headers(self, username: str, *, mode: str | None = None) -> dict[str, str]:
        """Return authenticated headers for a user, if present."""
        selected_mode = self._selected_mode(mode)
        session = self._sessions.get((username, selected_mode))
        user = self._users.get(username)
        if session is None or user is None or not session.authenticated:
            return {}
        headers = user.auth_headers(selected_mode)
        if not headers:
            self._invalidate_session(username, selected_mode)
            return {}
        session.authentication_headers = dict(headers)
        return dict(session.authentication_headers)

    def register_user(self, username: str, email: str, password: str, *, mode: str | None = None) -> SyntheticUser | None:
        """Register a synthetic user over HTTP and store it in memory."""
        selected_mode = self._selected_mode(mode)
        self._validate_password(password)
        if not isinstance(username, str) or not username.strip() or not isinstance(email, str) or not email.strip():
            raise ValueError("username and email must be non-empty strings.")
        username = username.strip()
        email = email.strip().lower()
        if username in self._users or any(user.email.lower() == email for user in self._users.values()):
            return None
        result = self.client.register_user(username, email, password, mode=selected_mode)
        if result.status_code != 201 or not isinstance(result.payload, dict):
            return None

        user_payload = result.payload.get("user") if isinstance(result.payload.get("user"), dict) else {}
        user = SyntheticUser(
            username=username,
            email=email,
            password=password,
            user_id=user_payload.get("id"),
            _default_mode=self.mode,
        )
        self._users[username] = user
        return user

    def login_user(self, user: SyntheticUser | None = None, *, username: str | None = None, password: str | None = None, mode: str | None = None) -> AuthSession:
        """Authenticate a synthetic user via HTTP and store the bearer token in memory."""
        selected_mode = self._selected_mode(mode)
        if user is None:
            if not username or not password:
                raise ValueError("Either a SyntheticUser or both username and password are required.")
            user = self._users.get(username) or SyntheticUser(username=username, email=self.generate_email(username), password=password)
            if username not in self._users:
                user._default_mode = self.mode
                self._users[username] = user
        elif self._users.get(user.username) not in (None, user):
            raise ValueError("A different synthetic user with this username is already managed.")
        else:
            self._users.setdefault(user.username, user)

        self._validate_password(user.password)
        self._invalidate_session(user.username, selected_mode)
        user.clear_token(selected_mode)

        result = self.client.login_user(user.username, user.password, mode=selected_mode)
        if result.status_code != 200 or not isinstance(result.payload, dict):
            session = AuthSession(
                user=user,
                authenticated=False,
                authentication_headers={},
                session_metadata={"mode": selected_mode, "status_code": result.status_code, "error": result.error},
            )
            self._sessions[(user.username, selected_mode)] = session
            return session

        payload = result.payload
        user_payload = payload.get("user") if isinstance(payload.get("user"), dict) else {}
        token = payload.get("token")
        try:
            expires_at = self._parse_expiry(payload.get("expires_at"))
        except ValueError:
            expires_at = None
            token = None
        if isinstance(token, str):
            token = token.strip()
            try:
                if str(uuid.UUID(token)) != token:
                    token = None
            except (ValueError, AttributeError):
                token = None
        if (
            not isinstance(user_payload.get("username"), str)
            or user_payload.get("username") != user.username
            or not isinstance(token, str)
            or not token.strip()
        ):
            token = None

        if token is None:
            session = AuthSession(
                user=user,
                authenticated=False,
                authentication_headers={},
                session_metadata={
                    "mode": selected_mode,
                    "status_code": result.status_code,
                    "error": "Login response did not contain valid session credentials.",
                },
            )
            self._sessions[(user.username, selected_mode)] = session
            return session

        user.set_token(selected_mode, token.strip(), expires_at)
        user.user_id = user_payload.get("id") if user.user_id is None else user.user_id

        headers = user.auth_headers(selected_mode)
        session = AuthSession(
            user=user,
            authenticated=bool(headers),
            authentication_headers=headers,
            session_metadata={
                "mode": selected_mode,
                "status_code": result.status_code,
                "expires_at": payload.get("expires_at"),
            },
        )
        self._sessions[(user.username, selected_mode)] = session
        return session

    def logout_user(self, user: SyntheticUser | str, *, mode: str | None = None) -> bool:
        """Invalidate a user token through the ShopZone logout endpoint."""
        if isinstance(user, str):
            user = self._users.get(user)
        if user is None:
            return False

        selected_mode = self._selected_mode(mode)
        headers = user.auth_headers(selected_mode)
        if not headers:
            return False

        try:
            result = self.client.post("/auth/logout", mode=selected_mode, headers=headers)
            server_invalidated = (
                result.status_code == 200
                and isinstance(result.payload, dict)
                and result.payload.get("message") == "Successfully logged out"
            )
        except Exception:
            server_invalidated = False

        user.clear_token(selected_mode)
        session = self._sessions.get((user.username, selected_mode))
        if session is not None:
            session.authenticated = False
            session.authentication_headers.clear()
            session.session_metadata["logout_attempted"] = True
            session.session_metadata["server_invalidation_confirmed"] = server_invalidated
        return server_invalidated

    def register_and_login(self, *, username: str | None = None, email: str | None = None, password: str | None = None, mode: str | None = None) -> AuthSession | None:
        """Convenience wrapper for a full registration + login flow."""
        selected_mode = self._selected_mode(mode)
        generated_username = username or self.generate_username()
        generated_email = email or self.generate_email(generated_username)
        generated_password = password or self.generate_password()
        user = self.register_user(generated_username, generated_email, generated_password, mode=selected_mode)
        if user is None:
            return None
        return self.login_user(user, mode=selected_mode)
