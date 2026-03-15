"""
Database models for Threat Watch
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, Integer, String, DateTime, Float, Text, Index, ForeignKey, UniqueConstraint, select
from shared.models.base import Base


class ThreatEvent(Base):
    """
    Represents an IDS/IPS threat event from UniFi
    """
    __tablename__ = "threats_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    controller_id = Column(Integer, ForeignKey("controller_config.id"), nullable=False, index=True)

    # UniFi identifiers
    unifi_event_id = Column(String, nullable=False, index=True)
    flow_id = Column(String, nullable=True)

    # Timestamp
    timestamp = Column(DateTime, nullable=False, index=True)

    # Alert information
    signature = Column(String, nullable=True)  # inner_alert_signature
    signature_id = Column(Integer, nullable=True)  # inner_alert_signature_id
    severity = Column(Integer, nullable=True, index=True)  # inner_alert_severity
    category = Column(String, nullable=True, index=True)  # inner_alert_category / catname
    action = Column(String, nullable=True)  # inner_alert_action (alert, block)
    message = Column(Text, nullable=True)  # msg

    # Network information
    src_ip = Column(String, nullable=True, index=True)
    src_port = Column(Integer, nullable=True)
    src_mac = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True, index=True)
    dest_port = Column(Integer, nullable=True)
    dest_mac = Column(String, nullable=True)
    protocol = Column(String, nullable=True)  # proto
    app_protocol = Column(String, nullable=True)  # app_proto
    interface = Column(String, nullable=True)  # in_iface

    # Geolocation - Source
    src_country = Column(String, nullable=True)
    src_city = Column(String, nullable=True)
    src_latitude = Column(Float, nullable=True)
    src_longitude = Column(Float, nullable=True)
    src_asn = Column(String, nullable=True)
    src_org = Column(String, nullable=True)

    # Geolocation - Destination
    dest_country = Column(String, nullable=True)
    dest_city = Column(String, nullable=True)
    dest_latitude = Column(Float, nullable=True)
    dest_longitude = Column(Float, nullable=True)
    dest_asn = Column(String, nullable=True)
    dest_org = Column(String, nullable=True)

    # Metadata
    site_id = Column(String, nullable=True)
    archived = Column(Boolean, default=False, nullable=False)
    raw_data = Column(Text, nullable=True)  # Store full JSON for reference

    # Ignore list tracking
    ignored = Column(Boolean, default=False, nullable=False, index=True)
    ignored_by_rule_id = Column(Integer, nullable=True)

    # When we fetched this event
    fetched_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Indexes for common queries
    __table_args__ = (
        UniqueConstraint('controller_id', 'unifi_event_id', name='uix_threat_event_controller_unifi_id'),
        Index('ix_threats_events_timestamp_severity', 'timestamp', 'severity'),
        Index('ix_threats_events_controller_timestamp', 'controller_id', 'timestamp'),
        Index('ix_threats_events_src_ip_timestamp', 'src_ip', 'timestamp'),
    )

    def __repr__(self):
        return f"<ThreatEvent(id={self.id}, signature={self.signature}, src_ip={self.src_ip}, severity={self.severity})>"


class ThreatWebhookConfig(Base):
    """
    Stores webhook configurations for sending threat event notifications
    """
    __tablename__ = "threats_webhook_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    controller_id = Column(Integer, ForeignKey("controller_config.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    webhook_type = Column(String, nullable=False)  # 'slack', 'discord', 'n8n'
    url = Column(String, nullable=False)

    # Severity triggers (1 = high, 2 = medium, 3 = low)
    min_severity = Column(Integer, default=2, nullable=False)  # Only alert on events at or below this severity

    # Event type triggers
    event_alert = Column(Boolean, default=True, nullable=False)  # IDS alerts
    event_block = Column(Boolean, default=True, nullable=False)  # IPS blocks

    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_triggered = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<ThreatWebhookConfig(name={self.name}, type={self.webhook_type}, enabled={self.enabled})>"


class ThreatIgnoreRule(Base):
    """
    Stores IP addresses to ignore for specific severity levels.
    Allows filtering out noise from known devices (e.g., Home Assistant SNMP queries).
    """
    __tablename__ = "threats_ignore_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    controller_id = Column(Integer, ForeignKey("controller_config.id"), nullable=False, index=True)
    ip_address = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)  # e.g., "Home Assistant"

    # Severity levels to ignore (1=High, 2=Medium, 3=Low)
    ignore_high = Column(Boolean, default=False, nullable=False)
    ignore_medium = Column(Boolean, default=True, nullable=False)
    ignore_low = Column(Boolean, default=True, nullable=False)

    # Match configuration
    match_source = Column(Boolean, default=True, nullable=False)       # Match when IP is src_ip
    match_destination = Column(Boolean, default=False, nullable=False)  # Match when IP is dest_ip

    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Stats
    events_ignored = Column(Integer, default=0, nullable=False)
    last_matched = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<ThreatIgnoreRule(ip={self.ip_address}, enabled={self.enabled})>"


def scoped_threat_events_query(controller_id: int):
    """Base query for threat events within a controller context."""
    return select(ThreatEvent).where(ThreatEvent.controller_id == controller_id)


def scoped_threat_webhooks_query(controller_id: int):
    """Base query for threat webhooks within a controller context."""
    return select(ThreatWebhookConfig).where(ThreatWebhookConfig.controller_id == controller_id)


def scoped_threat_ignore_rules_query(controller_id: int):
    """Base query for threat ignore rules within a controller context."""
    return select(ThreatIgnoreRule).where(ThreatIgnoreRule.controller_id == controller_id)
