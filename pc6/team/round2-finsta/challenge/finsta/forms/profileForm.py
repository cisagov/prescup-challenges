from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo


class ProfileForm(FlaskForm):
    bio = TextAreaField('Bio', validators=[DataRequired(), Length(max=40)])
    style = TextAreaField('Style your profile with CSS!')
        
    submit = SubmitField('Create')
    
