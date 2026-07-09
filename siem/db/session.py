"""
Database engine / session factory.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from siem.config import config
from siem.db.models import Base


def get_engine(echo: bool = False):
    return create_engine(config.sqlalchemy_uri, echo=echo, future=True)


def get_session_factory(engine=None):
    engine = engine or get_engine()
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db(engine=None):
    """Create all tables if they don't already exist (idempotent)."""
    engine = engine or get_engine()
    Base.metadata.create_all(engine)
    return engine
