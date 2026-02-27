from sqlalchemy import Column, Integer, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from db import Base

class Auction(Base):
    __tablename__ = 'auctions'

    id = Column(Integer, primary_key=True, autoincrement=True)
    warehouse_id = Column(Integer)
    user_id = Column(Integer, ForeignKey('users.id'))
    public = Column(Boolean, default=0)
    open = Column(Boolean, default=0)
    starting_bid = Column(Float)
    end_date = Column(DateTime)
    winner = Column(Integer, ForeignKey('users.id'))
    cover_image = Column(Integer)

    owner = relationship("User", foreign_keys=[user_id], back_populates="auctions")
    winning_user = relationship("User", foreign_keys=[winner], back_populates="winning_auctions")
    bids = relationship("Bid", back_populates="auction")
    alerts = relationship("Alert", back_populates="auction")
    cancellation = relationship("Cancellation", back_populates="auction", uselist=False)
    pickup_info = relationship("PickupInfo", back_populates="auction", uselist=False)