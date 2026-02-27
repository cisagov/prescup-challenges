from flask_wtf import FlaskForm
from wtforms import DecimalField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError

class BidForm(FlaskForm):
    amount = DecimalField("Bid Amount", places=2, validators=[DataRequired()])
    submit = SubmitField("Place Bid")

    def __init__(self, min_bid, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._min_bid = min_bid

    def validate_amount(self, field):
        if field.data < self._min_bid:
            raise ValidationError(f"Bid must be at least ${self._min_bid:.2f}")