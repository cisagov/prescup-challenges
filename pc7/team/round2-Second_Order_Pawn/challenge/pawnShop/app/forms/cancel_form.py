from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length

class CancellationRequestForm(FlaskForm):
    reason = TextAreaField("Reason for Cancellation", validators=[DataRequired(), Length(min=10)])
    submit = SubmitField("Submit Request")
    
class AdminCancellationDecisionForm(FlaskForm):
    approve = SubmitField("Approve")
    deny = SubmitField("Deny")