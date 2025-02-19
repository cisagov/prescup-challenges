from dataclasses import dataclass
from flask_jwt_extended import get_jwt, verify_jwt_in_request
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy.orm import relationship


# this variable, db, will be used for all SQLAlchemy commands
db = SQLAlchemy()


class User(db.Model, UserMixin):
    '''Stores current users state'''
    __tablename__ = 'Users'
    username = db.Column(db.String(collation='NOCASE'), primary_key=True)
    bio = db.Column(db.String, default="Hey! I'm new to Finsta!")
    style = db.Column(db.String)
    password = db.Column(db.String)
    posts = relationship("Post", back_populates="user")

    def __init__(self, *args, **kwargs) -> None:
        self.userIsPremium = False
    
        super().__init__(*args, **kwargs)

    def get_id(self):
        return self.username


@dataclass
class Post(db.Model):
    id: int
    username: str
    title: str
    text: str
    tags: str

    __tablename__ = 'Posts'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, db.ForeignKey('Users.username'))
    title = db.Column(db.String)
    text = db.Column(db.String)
    draft = db.Column(db.Integer)
    tags = db.Column(db.String)
    user = relationship("User", back_populates="posts")
