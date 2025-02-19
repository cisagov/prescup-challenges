from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=40)])
    tags = StringField('Tag your post!', description="tag1~tag2~tag3...")
    text = TextAreaField('Body', validators=[DataRequired(), Length(max=100)])
        
    submit = SubmitField('Post!')
    
