from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 40)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
