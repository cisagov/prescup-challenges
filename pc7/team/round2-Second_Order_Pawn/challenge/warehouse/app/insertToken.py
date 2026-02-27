import os
import logging
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timezone

from models.item import Item 
from db import Session

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the token from the environment
token = os.getenv("sqlToken")
if not token:
    logger.error("Environment variable 'sqlToken' is not set. Aborting.")
    exit(1)

def main():
    session = Session()
    try:
        flag_item = Item(
            name="Token",
            description=f"Token: {token}",
            dropped_off=1,
            drop_off_date=datetime.now(timezone.utc),
            user_id=1
        )
        session.add(flag_item)
        session.commit()
        logger.info("Inserted flag item into the database.")
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Database error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    main()
