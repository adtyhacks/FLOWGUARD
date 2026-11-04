"""Runtime configuration for the FLOWGUARD HTTP assessment client."""

from __future__ import annotations

import os
import math
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlsplit

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
ALLOWED_TARGET_MODES = {"vulnerable", "secure"}


@dataclass(frozen=True, init=False)
class FlowGuardConfig:
    """Configuration for a FLOWGUARD target assessment.

    The assessment environment is restricted to local laboratory targets by default
    so the tool remains within the authorized ShopZone test environment.
    """

    base_url: str = "http://127.0.0.1:5000"
    target_mode: str = "secure"
    timeout: float = 5.0
    evidence_enabled: bool = True
    assessment_name: str = "default-assessment"
    safe_mode: bool = True
    allowed_local_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:5000",
        target_mode: str = "secure",
        timeout: float = 5.0,
        admin_key: str | None = None,
        evidence_enabled: bool = True,
        assessment_name: str = "default-assessment",
        safe_mode: bool = True,
        allowed_local_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "::1"),
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(self, "target_mode", target_mode)
        object.__setattr__(self, "timeout", timeout)
        object.__setattr__(self, "evidence_enabled", evidence_enabled)
        object.__setattr__(self, "assessment_name", assessment_name)
        object.__setattr__(self, "safe_mode", safe_mode)
        object.__setattr__(self, "allowed_local_hosts", allowed_local_hosts)
        object.__setattr__(self, "_admin_key", admin_key)
        object.__setattr__(self, "_extra_headers", dict(extra_headers or {}))
        self.__post_init__()

    @property
    def admin_key(self) -> str | None:
        return self._admin_key

    @property
    def extra_headers(self) -> dict[str, str]:
        return dict(self._extra_headers)

    def __post_init__(self) -> None:
        """Validate configuration values after initialization."""
        if not isinstance(self.base_url, str) or not self.base_url.strip():
            raise ValueError("base_url must be a non-empty URL string.")

        try:
            parsed = urlsplit(self.base_url.strip())
            port = parsed.port
        except ValueError as exc:
            raise ValueError("base_url must be a valid localhost URL.") from exc
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("base_url must use http or https.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain embedded credentials.")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query or fragment.")
        if any(ord(char) < 32 or char == "\\" for char in parsed.path):
            raise ValueError("base_url contains an invalid path.")

        host = (parsed.hostname or "").lower()
        configured_hosts = tuple(str(item).lower() for item in self.allowed_local_hosts)
        if not configured_hosts or not set(configured_hosts).issubset(LOCAL_HOSTS):
            raise ValueError("allowed_local_hosts may contain only localhost or loopback hosts.")
        if host not in LOCAL_HOSTS or host not in set(configured_hosts):
            raise ValueError(
                "FLOWGUARD may only target the local laboratory by default. "
                "Use a localhost or loopback host such as http://127.0.0.1:5000."
            )
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("base_url port must be between 1 and 65535.")

        mode = str(self.target_mode).lower()
        if mode not in ALLOWED_TARGET_MODES:
            raise ValueError("target_mode must be either 'vulnerable' or 'secure'.")

        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("timeout must be greater than zero.")

        base_path = parsed.path.rstrip("/")
        object.__setattr__(self, "base_url", f"{parsed.scheme}://{parsed.netloc}{base_path}")
        object.__setattr__(self, "target_mode", mode)
        object.__setattr__(self, "allowed_local_hosts", configured_hosts)

        if self.admin_key is not None:
            normalized_key = str(self.admin_key).strip()
            object.__setattr__(self, "_admin_key", normalized_key)
            if not normalized_key:
                raise ValueError("admin_key cannot be an empty string.")

    def to_dict(self) -> dict[str, Any]:
        """Return a safe configuration export with secrets redacted."""
        from .redaction import sanitize_value

        values = asdict(self)
        values["admin_key"] = self.admin_key
        values["extra_headers"] = self.extra_headers
        return sanitize_value(values)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "FlowGuardConfig":
        """Build a FlowGuardConfig from environment variables."""
        if env is None:
            try:
                from dotenv import load_dotenv
                load_dotenv(Path(__file__).resolve().parent.parent / ".env")
            except Exception:
                pass
            values = os.environ
        else:
            values = env
        return cls(
            base_url=values.get("FLOWGUARD_BASE_URL", "http://127.0.0.1:5000"),
            target_mode=values.get("FLOWGUARD_TARGET_MODE", "secure"),
            timeout=float(values.get("FLOWGUARD_TIMEOUT", "5.0")),
            admin_key=values.get("ADMIN_KEY"),
            evidence_enabled=values.get("FLOWGUARD_EVIDENCE_ENABLED", "true").lower() in {"1", "true", "yes"},
            assessment_name=values.get("FLOWGUARD_ASSESSMENT_NAME", "default-assessment"),
            safe_mode=values.get("FLOWGUARD_SAFE_MODE", "true").lower() in {"1", "true", "yes"},
        )

    def mode_url(self, mode: str | None = None) -> str:
        """Return a mode-specific base URL for ShopZone endpoints."""
        selected_mode = (mode or self.target_mode).lower()
        if selected_mode not in ALLOWED_TARGET_MODES:
            raise ValueError("mode must be either 'vulnerable' or 'secure'.")
        return f"{self.base_url}/{selected_mode}/api"
