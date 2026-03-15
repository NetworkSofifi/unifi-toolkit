"""
Controller registry model for multi-controller support.
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, Integer, String, DateTime, LargeBinary

from shared.models.base import Base


class ControllerConfig(Base):
    """
    Stores a UniFi controller entry in the controller registry.

    This table is the multi-controller replacement for the legacy single-row
    `unifi_config` table. During transition we keep both, with this registry
    as the primary source of truth for new code paths.
    """

    __tablename__ = "controller_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    controller_key = Column(String, unique=True, nullable=False, index=True)
    display_name = Column(String, nullable=False, default="Default Controller")

    controller_url = Column(String, nullable=False)

    # Legacy auth (optional if using API key)
    username = Column(String, nullable=True)
    password_encrypted = Column(LargeBinary, nullable=True)

    # UniFi OS auth (optional if using username/password)
    api_key_encrypted = Column(LargeBinary, nullable=True)

    site_id = Column(String, default="default", nullable=False)
    verify_ssl = Column(Boolean, default=False, nullable=False)
    is_unifi_os = Column(Boolean, default=False, nullable=False)
    last_successful_connection = Column(DateTime, nullable=True)

    # Registry metadata
    is_default = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        auth_type = "API Key" if self.api_key_encrypted else "Username/Password"
        return (
            f"<ControllerConfig(key={self.controller_key}, name={self.display_name}, "
            f"site={self.site_id}, auth={auth_type}, default={self.is_default})>"
        )
