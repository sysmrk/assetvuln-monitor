"""Container health is independent of temporary upstream API outages."""
from sqlalchemy import create_engine, text
from avm.settings import database_url
with create_engine(database_url()).connect() as conn:
    assert conn.execute(text('SELECT 1')).scalar() == 1
