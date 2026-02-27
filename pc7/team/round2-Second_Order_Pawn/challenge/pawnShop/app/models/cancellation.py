from sqlalchemy import Boolean, Column, Integer, Text, ForeignKey
from sqlalchemy.orm import relationship
from db import Base

class Cancellation(Base):
    __tablename__ = 'cancellations'

    id = Column(Integer, primary_key=True, autoincrement=True)
    auction_id = Column(Integer, ForeignKey('auctions.id'))
    reason = Column(Text)
    approved = Column(Boolean)

    auction = relationship("Auction", back_populates="cancellation")
