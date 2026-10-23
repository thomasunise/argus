from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base


def make_db(url: str):
    if url.startswith('sqlite:///') and not url.startswith('sqlite:///:memory:'):
        Path(url.removeprefix('sqlite:///')).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args={'check_same_thread': False} if url.startswith('sqlite:') else {}, pool_pre_ping=True)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def init_db(engine):
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(factory):
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
