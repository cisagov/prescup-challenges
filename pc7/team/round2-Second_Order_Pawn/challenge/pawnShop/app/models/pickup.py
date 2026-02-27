from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from db import Base

class PickupInfo(Base):
    __tablename__ = "pickups"

    id = Column(Integer, primary_key=True, autoincrement=True)

    item_id = Column(Integer, nullable=False, unique=True)
    auction_id = Column(Integer, ForeignKey("auctions.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    name = Column(String, nullable=False)
    email = Column(String, nullable=False)

    # Relationships
    auction = relationship("Auction", back_populates="pickup_info")