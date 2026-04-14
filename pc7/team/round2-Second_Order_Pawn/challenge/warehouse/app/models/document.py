# models/documents.py
from sqlalchemy import Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import relationship
from db import Base

class Document(Base):
    __tablename__ = 'documents'

    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("items.id"), nullable=False)
    filename = Column(String(100))
    description = Column(Text)
    item_metadata = Column("metadata", Text, key="item_metadata")

    item = relationship("Item", back_populates="documents")
