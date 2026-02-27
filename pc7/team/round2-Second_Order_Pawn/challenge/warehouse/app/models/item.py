from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
from db import Base

class Item(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True)
    name = Column(Text)
    description = Column(Text)
    dropped_off = Column(Integer)
    drop_off_date = Column(DateTime)
    user_id = Column(Integer)
    
    documents = relationship("Document", back_populates="item")