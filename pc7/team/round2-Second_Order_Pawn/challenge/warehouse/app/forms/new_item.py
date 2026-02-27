from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, FormField, FieldList, ValidationError
from wtforms.validators import DataRequired, Length

class DocumentForm(FlaskForm):
    class Meta:
        csrf = False
    file = FileField("File", validators=[DataRequired()])
    documentDescription = StringField("Document Description", validators=[DataRequired(), Length(max=100)])

class NewItemForm(FlaskForm):
    name = StringField("Item Name", validators=[DataRequired(), Length(max=1000)])
    description = TextAreaField("Item Description", validators=[DataRequired(), Length(max=1000)])
    documents = FieldList(FormField(DocumentForm), min_entries=1)
    
    def validate_documents(self, field):
        if not any(subform.file.data and subform.file.data.filename for subform in field.entries):
            raise ValidationError("At least one document file must be uploaded.")
