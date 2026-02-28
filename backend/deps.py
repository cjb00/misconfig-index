from __future__ import annotations

from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .config import settings
from .models import Base

# SQLite requires check_same_thread=False; PostgreSQL does not need it.
_connect_args = {"check_same_thread": False} if settings.is_sqlite else {}

engine = create_engine(
    settings.DATABASE_URL,
    future=True,
    connect_args=_connect_args,
    pool_pre_ping=True,   # reconnect automatically on stale connections
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    future=True,
)


def init_db() -> None:
    """
    Create all tables that don't already exist.
    Safe to call on every startup — SQLAlchemy skips tables that are present.
    """
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
