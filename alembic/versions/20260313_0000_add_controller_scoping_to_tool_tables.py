"""Add controller scoping to persisted tool tables

Revision ID: c9f4d2a1b7e0
Revises: b5c9e2d7f1a3
Create Date: 2026-03-13 00:00:00.000000+00:00

"""
from typing import Optional, Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c9f4d2a1b7e0"
down_revision: Union[str, None] = "b5c9e2d7f1a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(connection, table_name: str) -> bool:
    inspector = sa.inspect(connection)
    return table_name in inspector.get_table_names()


def _has_column(connection, table_name: str, column_name: str) -> bool:
    inspector = sa.inspect(connection)
    return any(col["name"] == column_name for col in inspector.get_columns(table_name))


def _ensure_controller_registry_table(connection) -> None:
    if _has_table(connection, "controller_config"):
        return

    op.create_table(
        "controller_config",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("controller_key", sa.String(), nullable=False),
        sa.Column("display_name", sa.String(), nullable=False),
        sa.Column("controller_url", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("password_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("api_key_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("site_id", sa.String(), nullable=False),
        sa.Column("verify_ssl", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_unifi_os", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_successful_connection", sa.DateTime(), nullable=True),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("controller_key", name="uq_controller_config_controller_key"),
    )
    op.create_index("ix_controller_config_controller_key", "controller_config", ["controller_key"], unique=False)


def _ensure_default_controller_row(connection) -> Optional[int]:
    row = connection.execute(
        sa.text(
            """
            SELECT id
            FROM controller_config
            WHERE is_default = 1
            ORDER BY id ASC
            LIMIT 1
            """
        )
    ).mappings().first()
    if row:
        return int(row["id"])

    first_row = connection.execute(
        sa.text("SELECT id FROM controller_config ORDER BY id ASC LIMIT 1")
    ).mappings().first()
    if first_row:
        default_id = int(first_row["id"])
        connection.execute(
            sa.text("UPDATE controller_config SET is_default = CASE WHEN id = :id THEN 1 ELSE 0 END"),
            {"id": default_id},
        )
        return default_id

    legacy = connection.execute(
        sa.text(
            """
            SELECT controller_url, username, password_encrypted, api_key_encrypted, site_id, verify_ssl, is_unifi_os
            FROM unifi_config
            WHERE id = 1
            """
        )
    ).mappings().first()

    if legacy:
        connection.execute(
            sa.text(
                """
                INSERT INTO controller_config (
                    controller_key, display_name, controller_url, username,
                    password_encrypted, api_key_encrypted, site_id, verify_ssl,
                    is_unifi_os, is_default, is_active, created_at, updated_at
                ) VALUES (
                    :controller_key, :display_name, :controller_url, :username,
                    :password_encrypted, :api_key_encrypted, :site_id, :verify_ssl,
                    :is_unifi_os, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                )
                """
            ),
            {
                "controller_key": "default",
                "display_name": "Default Controller",
                "controller_url": legacy["controller_url"],
                "username": legacy["username"],
                "password_encrypted": legacy["password_encrypted"],
                "api_key_encrypted": legacy["api_key_encrypted"],
                "site_id": legacy["site_id"] or "default",
                "verify_ssl": bool(legacy["verify_ssl"]),
                "is_unifi_os": bool(legacy["is_unifi_os"]),
            },
        )
    default_row = connection.execute(
        sa.text("SELECT id FROM controller_config WHERE is_default = 1 ORDER BY id ASC LIMIT 1")
    ).mappings().first()
    if default_row:
        return int(default_row["id"])
    return None


def _table_has_rows(connection, table_name: str) -> bool:
    row = connection.execute(sa.text(f"SELECT 1 FROM {table_name} LIMIT 1")).first()
    return row is not None


def _add_controller_id_column(table_name: str) -> None:
    with op.batch_alter_table(table_name, schema=None) as batch_op:
        batch_op.add_column(sa.Column("controller_id", sa.Integer(), nullable=True))


def _set_controller_id_for_existing_rows(connection, table_name: str, controller_id: int) -> None:
    connection.execute(
        sa.text(f"UPDATE {table_name} SET controller_id = :controller_id WHERE controller_id IS NULL"),
        {"controller_id": controller_id},
    )


def _finalize_controller_id_column(table_name: str, index_name: str) -> None:
    with op.batch_alter_table(table_name, schema=None) as batch_op:
        batch_op.create_foreign_key(
            f"fk_{table_name}_controller_id",
            "controller_config",
            ["controller_id"],
            ["id"],
        )
        batch_op.alter_column("controller_id", existing_type=sa.Integer(), nullable=False)
        batch_op.create_index(index_name, ["controller_id"], unique=False)


def upgrade() -> None:
    connection = op.get_bind()

    _ensure_controller_registry_table(connection)
    default_controller_id = _ensure_default_controller_row(connection)

    scoped_tables = [
        ("stalker_tracked_devices", "ix_stalker_tracked_devices_controller_id"),
        ("stalker_connection_history", "ix_stalker_connection_history_controller_id"),
        ("stalker_webhook_config", "ix_stalker_webhook_config_controller_id"),
        ("stalker_hourly_presence", "ix_stalker_hourly_presence_controller_id"),
        ("threats_events", "ix_threats_events_controller_id"),
        ("threats_webhook_config", "ix_threats_webhook_config_controller_id"),
        ("threats_ignore_rules", "ix_threats_ignore_rules_controller_id"),
    ]

    for table_name, _ in scoped_tables:
        if not _has_column(connection, table_name, "controller_id"):
            _add_controller_id_column(table_name)

    if default_controller_id is None:
        tables_with_data = [table_name for table_name, _ in scoped_tables if _table_has_rows(connection, table_name)]
        if tables_with_data:
            joined = ", ".join(tables_with_data)
            raise RuntimeError(
                "Migration cannot infer controller identity for existing tool data without "
                f"a configured controller. Tables with data: {joined}. "
                "Configure legacy unifi_config before upgrade or manually seed controller_config."
            )
    else:
        for table_name, _ in scoped_tables:
            _set_controller_id_for_existing_rows(connection, table_name, default_controller_id)

    for table_name, index_name in scoped_tables:
        _finalize_controller_id_column(table_name, index_name)

    with op.batch_alter_table("stalker_tracked_devices", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uix_stalker_device_controller_mac",
            ["controller_id", "mac_address"],
        )

    with op.batch_alter_table("stalker_connection_history", schema=None) as batch_op:
        batch_op.create_index(
            "ix_stalker_history_controller_device_connected",
            ["controller_id", "device_id", "connected_at"],
            unique=False,
        )

    with op.batch_alter_table("stalker_hourly_presence", schema=None) as batch_op:
        batch_op.drop_constraint("uix_device_hour_slot", type_="unique")
        batch_op.create_unique_constraint(
            "uix_controller_device_hour_slot",
            ["controller_id", "device_id", "day_of_week", "hour_of_day"],
        )

    with op.batch_alter_table("threats_events", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uix_threat_event_controller_unifi_id",
            ["controller_id", "unifi_event_id"],
        )
        batch_op.create_index(
            "ix_threats_events_controller_timestamp",
            ["controller_id", "timestamp"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("threats_events", schema=None) as batch_op:
        batch_op.drop_index("ix_threats_events_controller_timestamp")
        batch_op.drop_constraint("uix_threat_event_controller_unifi_id", type_="unique")
        batch_op.drop_index("ix_threats_events_controller_id")
        batch_op.drop_constraint("fk_threats_events_controller_id", type_="foreignkey")
        batch_op.drop_column("controller_id")

    with op.batch_alter_table("threats_ignore_rules", schema=None) as batch_op:
        batch_op.drop_index("ix_threats_ignore_rules_controller_id")
        batch_op.drop_constraint("fk_threats_ignore_rules_controller_id", type_="foreignkey")
        batch_op.drop_column("controller_id")

    with op.batch_alter_table("threats_webhook_config", schema=None) as batch_op:
        batch_op.drop_index("ix_threats_webhook_config_controller_id")
        batch_op.drop_constraint("fk_threats_webhook_config_controller_id", type_="foreignkey")
        batch_op.drop_column("controller_id")

    with op.batch_alter_table("stalker_hourly_presence", schema=None) as batch_op:
        batch_op.drop_constraint("uix_controller_device_hour_slot", type_="unique")
        batch_op.create_unique_constraint("uix_device_hour_slot", ["device_id", "day_of_week", "hour_of_day"])
        batch_op.drop_index("ix_stalker_hourly_presence_controller_id")
        batch_op.drop_constraint("fk_stalker_hourly_presence_controller_id", type_="foreignkey")
        batch_op.drop_column("controller_id")

    with op.batch_alter_table("stalker_webhook_config", schema=None) as batch_op:
        batch_op.drop_index("ix_stalker_webhook_config_controller_id")
        batch_op.drop_constraint("fk_stalker_webhook_config_controller_id", type_="foreignkey")
        batch_op.drop_column("controller_id")

    with op.batch_alter_table("stalker_connection_history", schema=None) as batch_op:
        batch_op.drop_index("ix_stalker_history_controller_device_connected")
        batch_op.drop_index("ix_stalker_connection_history_controller_id")
        batch_op.drop_constraint("fk_stalker_connection_history_controller_id", type_="foreignkey")
        batch_op.drop_column("controller_id")

    with op.batch_alter_table("stalker_tracked_devices", schema=None) as batch_op:
        batch_op.drop_constraint("uix_stalker_device_controller_mac", type_="unique")
        batch_op.drop_index("ix_stalker_tracked_devices_controller_id")
        batch_op.drop_constraint("fk_stalker_tracked_devices_controller_id", type_="foreignkey")
        batch_op.drop_column("controller_id")

    op.drop_index("ix_controller_config_controller_key", table_name="controller_config")
    op.drop_table("controller_config")
