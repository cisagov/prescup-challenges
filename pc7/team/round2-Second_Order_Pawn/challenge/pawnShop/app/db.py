import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

PAWN_DB_URL = os.getenv("PAWN_DB_URL")
WAREHOUSE_DB_URL = os.getenv("WAREHOUSE_DB_URL")

if not PAWN_DB_URL or not WAREHOUSE_DB_URL:
    raise RuntimeError("Missing required environment variables: PAWN_DB_URL and/or WAREHOUSE_DB_URL")

engine = create_engine(PAWN_DB_URL,future=True, pool_pre_ping=True, pool_recycle=1800)
Session = sessionmaker(bind=engine)
Base = declarative_base()

engine_warehouse = create_engine(WAREHOUSE_DB_URL, future=True, pool_pre_ping=True, pool_recycle=1800)