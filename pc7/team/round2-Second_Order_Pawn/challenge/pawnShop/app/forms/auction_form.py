from flask_wtf import FlaskForm
from wtforms import DecimalField, DateTimeLocalField, RadioField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError
from datetime import datetime, timezone
from db import engine_warehouse
from sqlalchemy.sql import text
from flask_login import current_user

def OwnsCoverImage():
    def _validate(form, field):
        if field.data is None:
            return
        doc_id = field.data
        if not isinstance(field.data, int):
            raise ValidationError("Invalid document selection.")
        with engine_warehouse.connect() as conn:
            row = conn.execute(text(f"""
                SELECT items.user_id
                FROM documents
                JOIN items ON documents.item_id = items.id
                WHERE documents.id = {doc_id}
            """)).fetchone()
            if not row or row[0] != current_user.id:
                raise ValidationError("You do not own the selected document.")
    return _validate

def FutureDateOnly():
    def _check(form, field):
        if field.data.tzinfo is None:
            field_data = field.data.replace(tzinfo=timezone.utc)
        else:
            field_data = field.data

        if field_data <= datetime.now(timezone.utc):
            raise ValidationError("End date must be in the future.")
    return _check

class CreateAuctionForm(FlaskForm):
    starting_bid = DecimalField("Starting Bid ($)", places=2, validators=[
        DataRequired(), NumberRange(min=0.01)
    ])
    end_date = DateTimeLocalField("Auction End Date", format="%Y-%m-%dT%H:%M", validators=[
        DataRequired(), FutureDateOnly()
    ])
    cover_image = RadioField("Cover Image", choices=[], coerce=int, validators=[DataRequired(), OwnsCoverImage()])
    submit = SubmitField("Create Auction")

class CloseAuctionForm(FlaskForm):
    submit = SubmitField("Close Bidding")
    
class CancelAuctionForm(FlaskForm):
    submit = SubmitField("Cancel Auction")