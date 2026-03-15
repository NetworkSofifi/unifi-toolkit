"""Safety tests for controller bootstrap migration helpers."""
import importlib.util
from pathlib import Path

from sqlalchemy import create_engine, text


def _load_migration_module():
    migration_path = (
        Path(__file__).parent.parent
        / "alembic"
        / "versions"
        / "20260313_0000_add_controller_scoping_to_tool_tables.py"
    )
    spec = importlib.util.spec_from_file_location("migration_controller_scoping", migration_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _create_core_tables(connection):
    connection.execute(
        text(
            """
            CREATE TABLE controller_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                controller_key TEXT NOT NULL,
                display_name TEXT NOT NULL,
                controller_url TEXT NOT NULL,
                username TEXT,
                password_encrypted BLOB,
                api_key_encrypted BLOB,
                site_id TEXT NOT NULL,
                verify_ssl BOOLEAN NOT NULL DEFAULT 0,
                is_unifi_os BOOLEAN NOT NULL DEFAULT 0,
                last_successful_connection DATETIME,
                is_default BOOLEAN NOT NULL DEFAULT 0,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at DATETIME,
                updated_at DATETIME
            )
            """
        )
    )
    connection.execute(text("CREATE TABLE unifi_config (id INTEGER PRIMARY KEY, controller_url TEXT, username TEXT, password_encrypted BLOB, api_key_encrypted BLOB, site_id TEXT, verify_ssl BOOLEAN, is_unifi_os BOOLEAN)"))


def test_default_controller_helper_returns_none_without_legacy_data():
    module = _load_migration_module()
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_core_tables(connection)
        default_id = module._ensure_default_controller_row(connection)
        assert default_id is None


def test_default_controller_helper_materializes_legacy_row():
    module = _load_migration_module()
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_core_tables(connection)
        connection.execute(
            text(
                """
                INSERT INTO unifi_config
                (id, controller_url, username, password_encrypted, api_key_encrypted, site_id, verify_ssl, is_unifi_os)
                VALUES
                (1, 'https://192.168.1.1', 'admin', X'01', NULL, 'default', 0, 1)
                """
            )
        )
        default_id = module._ensure_default_controller_row(connection)
        assert isinstance(default_id, int)

        row = connection.execute(
            text("SELECT controller_key, display_name, controller_url, is_default FROM controller_config WHERE id = :id"),
            {"id": default_id},
        ).mappings().first()
        assert row is not None
        assert row["controller_key"] == "default"
        assert row["display_name"] == "Default Controller"
        assert row["controller_url"] == "https://192.168.1.1"
        assert row["is_default"] == 1


def test_default_controller_helper_marks_first_row_when_missing_default():
    module = _load_migration_module()
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        _create_core_tables(connection)
        connection.execute(
            text(
                """
                INSERT INTO controller_config
                (controller_key, display_name, controller_url, site_id, verify_ssl, is_unifi_os, is_default, is_active, created_at, updated_at)
                VALUES
                ('a', 'A', 'https://a.local', 'default', 0, 1, 0, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                ('b', 'B', 'https://b.local', 'default', 0, 1, 0, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """
            )
        )
        default_id = module._ensure_default_controller_row(connection)
        row = connection.execute(
            text("SELECT id, controller_key, is_default FROM controller_config WHERE id = :id"),
            {"id": default_id},
        ).mappings().first()
        assert row is not None
        assert row["controller_key"] == "a"
        assert row["is_default"] == 1
