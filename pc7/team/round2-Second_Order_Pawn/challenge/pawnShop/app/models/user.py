from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from db import Base

class User(Base, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    role = Column(String(10))
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    last_login = Column(DateTime)

    auctions = relationship("Auction", back_populates="owner", foreign_keys="Auction.user_id")
    winning_auctions = relationship("Auction", back_populates="winning_user", foreign_keys="Auction.winner")
    bids = relationship("Bid", back_populates="user")
