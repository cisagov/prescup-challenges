# forms.py
from flask_wtf import FlaskForm
from wtforms import SelectField, StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Optional

class SupportTicketForm(FlaskForm):
    challenge = SelectField(
        "Challenge",
        choices=[
            ("", "— Select —"),
            ("0", "N/A"),
            ("1", "Kessel Run"),
            ("2", "Mindhunter"),
            ("3", "The Crucible"),
            ("4", "va_list Adventure"),
        ],
        validators=[DataRequired()]
    )
    title = StringField("Title", validators=[DataRequired(), Length(min=3, max=200)])
    summary = TextAreaField("Summary", validators=[DataRequired(), Length(min=3)])
    submit = SubmitField("Submit")

class CommentForm(FlaskForm):
    text = TextAreaField("Add a comment...", validators=[DataRequired(), Length(min=1)])
    submit = SubmitField("Comment")