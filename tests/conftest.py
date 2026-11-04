"""Pytest fixtures for ShopZone testing."""

import os
import shutil
from pathlib import Path
import pytest
from shopzone import create_app
from shopzone.config import TestingConfig
from shopzone.db import close_all_sessions, init_db, reset_db


@pytest.fixture(scope="session")
def test_config():
    """Create a TestingConfig with dedicated test database paths."""
    instance_dir = Path(__file__).resolve().parent.parent / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)
    return TestingConfig


@pytest.fixture(scope="function")
def app(test_config):
    """Create an application configured for testing with fresh databases."""
    app = create_app(config_class=test_config, init_database=True)
    app.config["TESTING"] = True
    
    with app.app_context():
        # Ensure fresh clean state for every test function
        reset_db(mode="all", config=test_config, seed=True)
        yield app
        close_all_sessions()


@pytest.fixture(scope="function")
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_databases(test_config):
    """Clean up test database files at the end of the test session."""
    yield
    close_all_sessions()
    for p in [test_config.VULN_DB_PATH, test_config.SEC_DB_PATH]:
        p = Path(p)
        for ext in ["", "-wal", "-shm"]:
            f = Path(f"{p}{ext}")
            if f.exists():
                try:
                    f.unlink()
                except Exception:
                    pass
