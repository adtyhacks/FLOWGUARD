"""Tests verifying physical database isolation, PRAGMAs, and minor unit currency."""

from pathlib import Path
from sqlalchemy import text
from shopzone.config import TestingConfig
from shopzone.db import get_engine, get_session_factory
from shopzone.models import Product, User


def test_physical_database_files_exist(app):
    """Verify that vulnerable and secure databases exist as distinct files on disk."""
    vuln_path = Path(TestingConfig.VULN_DB_PATH)
    sec_path = Path(TestingConfig.SEC_DB_PATH)
    
    assert vuln_path.exists(), f"Vulnerable DB file does not exist: {vuln_path}"
    assert sec_path.exists(), f"Secure DB file does not exist: {sec_path}"
    assert vuln_path.resolve() != sec_path.resolve(), "Database paths must not be identical!"


def test_sqlite_pragmas_enabled(app):
    """Verify SQLite WAL mode, foreign keys, and busy timeout on both database connections."""
    for mode in ["vulnerable", "secure"]:
        engine = get_engine(mode, TestingConfig)
        with engine.connect() as conn:
            # Foreign keys
            fk = conn.execute(text("PRAGMA foreign_keys;")).scalar()
            assert fk == 1, f"Foreign keys not enabled for {mode} engine"
            
            # WAL mode
            journal = conn.execute(text("PRAGMA journal_mode;")).scalar()
            assert journal.lower() == "wal", f"Journal mode not WAL for {mode} engine (got {journal})"
            
            # Busy timeout
            timeout = conn.execute(text("PRAGMA busy_timeout;")).scalar()
            assert timeout >= 5000, f"Busy timeout less than 5000ms for {mode} engine (got {timeout})"


def test_currency_minor_units_enforced(app):
    """Verify that all product catalog prices are strictly stored as integer minor units."""
    for mode in ["vulnerable", "secure"]:
        session_factory = get_session_factory(mode, TestingConfig)
        session = session_factory()
        try:
            products = session.query(Product).all()
            assert len(products) > 0, f"No products seeded in {mode} database"
            for p in products:
                assert isinstance(p.price_minor_units, int), f"Product {p.id} price is not an integer!"
                assert p.price_minor_units > 0, f"Product {p.id} price must be positive!"
        finally:
            session.close()


def test_cross_database_user_isolation(client):
    """Registering a synthetic user in vulnerable mode must NOT create a user in secure mode."""
    user_payload = {
        "username": "isolated_test_user",
        "email": "isolated@flowguard.local",
        "password": "Password123!",
    }
    
    # 1. Register in vulnerable mode
    res_vuln = client.post("/vuln/api/auth/register", json=user_payload)
    assert res_vuln.status_code == 201, f"Vuln registration failed: {res_vuln.get_json()}"
    
    # 2. Login in vulnerable mode should succeed
    login_vuln = client.post("/vuln/api/auth/login", json={
        "username": "isolated_test_user",
        "password": "Password123!",
    })
    assert login_vuln.status_code == 200
    assert "token" in login_vuln.get_json()
    
    # 3. Attempting to login with the same credentials in secure mode MUST fail (401)
    login_sec = client.post("/sec/api/auth/login", json={
        "username": "isolated_test_user",
        "password": "Password123!",
    })
    assert login_sec.status_code == 401
    
    # 4. Verify directly in secure database that user does not exist
    sec_factory = get_session_factory("secure", TestingConfig)
    sec_session = sec_factory()
    try:
        user_in_sec = sec_session.query(User).filter_by(username="isolated_test_user").first()
        assert user_in_sec is None, "User registered in vulnerable DB leaked into secure DB!"
    finally:
        sec_session.close()
