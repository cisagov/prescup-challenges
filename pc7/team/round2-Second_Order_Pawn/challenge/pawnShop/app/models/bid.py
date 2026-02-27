from sqlalchemy import Column, DateTime, Integer, Float, ForeignKey
from sqlalchemy.orm import relationship
from db import Base

class Bid(Base):
    __tablename__ = 'bids'

    id = Column(Integer, primary_key=True, autoincrement=True)
    auction_id = Column(Integer, ForeignKey('auctions.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    bid = Column(Float)
    timestamp = Column(DateTime)

    auction = relationship("Auction", back_populates="bids")
    user = relationship("User", back_populates="bids")
