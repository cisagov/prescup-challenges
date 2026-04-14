from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from db import Base

class PawnItem(Base):
    __tablename__ = 'pawn'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100))
    description = Column(Text)
    category = Column(String(100))
    item_condition = Column(String(100))
    price = Column(Float)
    image = Column(String(100))
    listed_on = Column(DateTime)
