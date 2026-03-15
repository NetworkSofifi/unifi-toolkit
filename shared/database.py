"""
Database connection and session management for UI Toolkit
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from typing import AsyncGenerator
from pathlib import Path
from shared.config import get_settings
from shared.models.base import Base
import logging

logger = logging.getLogger(__name__)


class Database:
    """
    Manages database connection and sessions
    """
    def __init__(self):
        self.engine = None
        self.async_session_factory = None

    async def init_db(self):
        """
        Initialize database connection and create tables
        """
        settings = get_settings()

        # Ensure data directory exists and is writable (for SQLite database)
        if settings.database_url.startswith("sqlite"):
            # Extract path from database URL (e.g., sqlite+aiosqlite:///./data/db.db)
            db_path = settings.database_url.split("///")[-1]
            db_dir = Path(db_path).parent
            try:
                db_dir.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                logger.error(
                    f"Cannot create data directory: {db_dir.resolve()}. "
                    f"Create it on the host with: mkdir -p ./data && chown 1000:1000 ./data"
                )
                raise
            logger.info(f"Ensured data directory exists: {db_dir}")

        # Create async engine
        self.engine = create_async_engine(
            settings.database_url,
            echo=settings.log_level.upper() == "DEBUG"
        )

        # Create session factory
        self.async_session_factory = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        # Import all models to ensure they're registered with Base
        from shared.models.unifi_config import UniFiConfig
        from shared.models.controller_config import ControllerConfig
        # Tool models will be imported by their respective tools

        # Create all tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database initialized successfully")

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Get an async database session

        Yields:
            AsyncSession: Database session
        """
        if not self.async_session_factory:
            raise RuntimeError("Database not initialized. Call init_db() first.")

        async with self.async_session_factory() as session:
            yield session

    async def close(self):
        """
        Close database engine and cleanup resources
        """
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connection closed")


# Global database instance (singleton)
_database: Database = None


def get_database() -> Database:
    """
    Get the global database instance

    Returns:
        Database: The global database instance
    """
    global _database
    if _database is None:
        _database = Database()
    return _database


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI to get database sessions

    Usage:
        @app.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db_session)):
            ...

    Yields:
        AsyncSession: Database session
    """
    db = get_database()
    async for session in db.get_session():
        yield session
