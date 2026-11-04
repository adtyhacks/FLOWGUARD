"""Configuration management and environment variable validation for ShopZone."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root if present
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")


def validate_admin_key(admin_key: str | None) -> str:
    """Validate that ADMIN_KEY is configured and non-empty.
    
    Fail-fast requirement to avoid running with unauthenticated admin endpoints.
    """
    if not admin_key or not admin_key.strip():
        raise ValueError(
            "FATAL CONFIGURATION ERROR: ADMIN_KEY environment variable is required and cannot be empty. "
            "Please configure ADMIN_KEY in your environment or .env file before starting ShopZone."
        )
    return admin_key.strip()


def _resolve_db_path(env_val: str | None, default_filename: str) -> Path:
    """Resolve database path relative to PROJECT_ROOT if not already absolute."""
    if not env_val:
        return PROJECT_ROOT / "instance" / default_filename
    p = Path(env_val)
    return p.resolve() if p.is_absolute() else (PROJECT_ROOT / p).resolve()


class Config:
    """Base application configuration."""
    
    PROJECT_ROOT = PROJECT_ROOT
    INSTANCE_DIR = PROJECT_ROOT / "instance"
    
    # Network
    HOST = os.getenv("SHOPZONE_HOST", "127.0.0.1")
    PORT = int(os.getenv("SHOPZONE_PORT", "5000"))
    DEBUG = os.getenv("SHOPZONE_DEBUG", "False").lower() in ("true", "1", "yes")
    
    # Required Admin Key (validated on class load / instantiation)
    ADMIN_KEY = validate_admin_key(os.getenv("ADMIN_KEY"))
    
    # Physical SQLite Database Paths
    VULN_DB_PATH = _resolve_db_path(os.getenv("VULN_DB_PATH"), "shopzone_vuln.db")
    SEC_DB_PATH = _resolve_db_path(os.getenv("SEC_DB_PATH"), "shopzone_sec.db")
    
    # Session Token Lifetime (in seconds, default 2 hours)
    TOKEN_LIFETIME_SECONDS = int(os.getenv("TOKEN_LIFETIME_SECONDS", "7200"))


class TestingConfig(Config):
    """Configuration used during automated tests with temporary test databases."""
    
    TESTING = True
    DEBUG = False
    ADMIN_KEY = "test_admin_key_for_automated_testing_only"
    VULN_DB_PATH = Config.INSTANCE_DIR / "test_shopzone_vuln.db"
    SEC_DB_PATH = Config.INSTANCE_DIR / "test_shopzone_sec.db"
