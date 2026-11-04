"""Explicit database engine and session management for ShopZone.

Maintains two physically separate SQLite databases:
1. instance/shopzone_vuln.db (Vulnerable mode)
2. instance/shopzone_sec.db (Secure mode)
"""

import os
from pathlib import Path
from typing import Dict
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from .config import Config
from .models import Base
from .seeds import seed_database

# Cache of initialized engines and session factories by mode
_ENGINES: Dict[str, Engine] = {}
_SESSION_FACTORIES: Dict[str, scoped_session] = {}


def _configure_sqlite_pragmas(dbapi_connection, connection_record):
    """Enforce SQLite foreign keys, write-ahead logging (WAL), and busy timeout."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    cursor.execute("PRAGMA journal_mode = WAL;")
    cursor.execute("PRAGMA busy_timeout = 5000;")
    cursor.close()


def _get_config_value(config, key: str, default=None):
    """Retrieve config value whether config is a dict (like app.config) or an object/class."""
    if config is None:
        return getattr(Config, key, default)
    if hasattr(config, "get"):
        val = config.get(key)
        if val is not None:
            return val
    return getattr(config, key, default)


def get_db_path(mode: str, config=None) -> Path:
    """Return the absolute path to the SQLite file for the given mode."""
    if mode == "vulnerable":
        raw = Path(_get_config_value(config, "VULN_DB_PATH", Config.VULN_DB_PATH))
    elif mode == "secure":
        raw = Path(_get_config_value(config, "SEC_DB_PATH", Config.SEC_DB_PATH))
    else:
        raise ValueError(f"Invalid mode '{mode}'. Must be 'vulnerable' or 'secure'.")
    return raw if raw.is_absolute() else (Config.PROJECT_ROOT / raw).resolve()


def get_engine(mode: str, config=None) -> Engine:
    """Get or create the SQLAlchemy engine for the specified mode with explicit PRAGMAs."""
    vuln_path = _get_config_value(config, "VULN_DB_PATH", Config.VULN_DB_PATH)
    sec_path = _get_config_value(config, "SEC_DB_PATH", Config.SEC_DB_PATH)
    cache_key = f"{mode}_{str(vuln_path)}_{str(sec_path)}"
    
    if cache_key in _ENGINES:
        return _ENGINES[cache_key]
        
    db_path = get_db_path(mode, config)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    db_url = f"sqlite:///{db_path.as_posix()}"
    engine = create_engine(
        db_url,
        echo=False,
        connect_args={"check_same_thread": False, "timeout": 5.0},
    )
    
    # Attach PRAGMA configuration listener
    event.listen(engine, "connect", _configure_sqlite_pragmas)
    
    _ENGINES[cache_key] = engine
    return engine


def get_session_factory(mode: str, config=None) -> scoped_session:
    """Get or create the thread-safe scoped session factory for the specified mode."""
    vuln_path = _get_config_value(config, "VULN_DB_PATH", Config.VULN_DB_PATH)
    sec_path = _get_config_value(config, "SEC_DB_PATH", Config.SEC_DB_PATH)
    cache_key = f"{mode}_{str(vuln_path)}_{str(sec_path)}"
    
    if cache_key in _SESSION_FACTORIES:
        return _SESSION_FACTORIES[cache_key]
        
    engine = get_engine(mode, config)
    factory = scoped_session(
        sessionmaker(
            bind=engine,
            autocommit=False,
            autoflush=False,
            expire_on_commit=False,
        )
    )
    
    _SESSION_FACTORIES[cache_key] = factory
    return factory


def _ensure_mode_schema(engine: Engine, mode: str) -> None:
    """Enforce mode-specific schema constraints.
    
    Secure DB: Enforces globally single-use coupon constraint via unique index.
    Vulnerable DB: Removes any legacy unique constraint so repeated redemption is permitted.
    """
    with engine.connect() as conn:
        if mode == "secure":
            conn.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS uq_coupon_global_redemption ON coupon_redemptions (coupon_id);")
            )
            conn.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS uq_order_idempotency ON orders (idempotency_key) WHERE idempotency_key IS NOT NULL;")
            )
            conn.commit()
        elif mode == "vulnerable":
            # 1. Drop standalone unique indices if present
            conn.execute(text("DROP INDEX IF EXISTS uq_coupon_global_redemption;"))
            conn.execute(text("DROP INDEX IF EXISTS uq_order_idempotency;"))
            
            # 2. Check if table schema contains an inline table UNIQUE constraint from legacy schema
            table_sql = conn.execute(
                text("SELECT sql FROM sqlite_master WHERE type='table' AND name='coupon_redemptions'")
            ).scalar()
            
            if table_sql and ("UNIQUE" in table_sql.upper() or "uq_coupon_global_redemption" in table_sql):
                # SQLite cannot drop inline table constraints with ALTER TABLE; recreate table without constraint
                conn.execute(text("PRAGMA foreign_keys = OFF;"))
                conn.execute(text("""
                    CREATE TABLE coupon_redemptions_clean (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        coupon_id INTEGER NOT NULL REFERENCES coupons(id),
                        user_id INTEGER NOT NULL REFERENCES users(id),
                        order_id INTEGER REFERENCES orders(id),
                        redeemed_at DATETIME NOT NULL
                    );
                """))
                conn.execute(text("""
                    INSERT INTO coupon_redemptions_clean (id, coupon_id, user_id, order_id, redeemed_at)
                    SELECT id, coupon_id, user_id, order_id, redeemed_at FROM coupon_redemptions;
                """))
                conn.execute(text("DROP TABLE coupon_redemptions;"))
                conn.execute(text("ALTER TABLE coupon_redemptions_clean RENAME TO coupon_redemptions;"))
                conn.execute(text("PRAGMA foreign_keys = ON;"))
            conn.commit()


def init_db(mode: str = "all", config=None, seed: bool = True) -> None:
    """Initialize SQLite database tables and populate seed data.
    
    Args:
        mode: 'vulnerable', 'secure', or 'all'
        config: Configuration object
        seed: Whether to populate default catalog and coupons
    """
    cfg = config or Config
    modes = ["vulnerable", "secure"] if mode == "all" else [mode]
    
    for m in modes:
        engine = get_engine(m, cfg)
        Base.metadata.create_all(bind=engine)
        _ensure_mode_schema(engine, m)
        
        if seed:
            session_factory = get_session_factory(m, cfg)
            session = session_factory()
            try:
                seed_database(session)
            finally:
                session.close()


def reset_db(mode: str = "all", config=None, seed: bool = True) -> None:
    """Completely reset the database tables and re-seed clean state."""
    cfg = config or Config
    modes = ["vulnerable", "secure"] if mode == "all" else [mode]
    
    for m in modes:
        engine = get_engine(m, cfg)
        # Drop all tables cleanly
        Base.metadata.drop_all(bind=engine)
        # Re-create all tables
        Base.metadata.create_all(bind=engine)
        _ensure_mode_schema(engine, m)
        
        if seed:
            session_factory = get_session_factory(m, cfg)
            session = session_factory()
            try:
                seed_database(session)
            finally:
                session.close()


def close_all_sessions() -> None:
    """Remove and close all active scoped sessions."""
    for factory in _SESSION_FACTORIES.values():
        factory.remove()
