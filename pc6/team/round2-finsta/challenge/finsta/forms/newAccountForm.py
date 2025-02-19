from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo


class NewAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=40)])
    password = PasswordField(validators=[Length(min=4, message='Too short')])
    confirm = PasswordField(validators=[EqualTo('password', 'Password mismatch')])
        
    submit = SubmitField('Create')
    
