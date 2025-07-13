from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, PasswordField, SelectField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, Email, NumberRange, Optional, Regexp, ValidationError
import bleach

class SecureForm(FlaskForm):
    """Base form with security enhancements"""
    
    def sanitize_data(self):
        """Sanitize all form data to prevent XSS"""
        for field_name, field in self._fields.items():
            if hasattr(field, 'data') and isinstance(field.data, str):
                field.data = bleach.clean(field.data, strip=True)

class LoginForm(SecureForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=50, message='Username must be 3-50 characters'),
        Regexp(r'^[a-zA-Z0-9_@.-]+$', message='Username contains invalid characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, max=128, message='Password must be 8-128 characters')
    ])

class ContactForm(SecureForm):
    name = StringField('Name', validators=[
        DataRequired(message='Name is required'),
        Length(min=2, max=100, message='Name must be 2-100 characters'),
        Regexp(r'^[a-zA-Z\s.-]+$', message='Name contains invalid characters')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address'),
        Length(max=100, message='Email too long')
    ])
    phone = StringField('Phone', validators=[
        Optional(),
        Regexp(r'^[\d\s\-\+\(\)]+$', message='Invalid phone number format'),
        Length(max=20, message='Phone number too long')
    ])
    service = SelectField('Service', choices=[
        ('tours', 'Motorcycle Tours'),
        ('rentals', 'Bike Rentals'),
        ('repairs', 'Bike Repairs'),
        ('general', 'General Inquiry')
    ], validators=[DataRequired(message='Please select a service')])
    message = TextAreaField('Message', validators=[
        DataRequired(message='Message is required'),
        Length(min=10, max=2000, message='Message must be 10-2000 characters')
    ])

class TourForm(SecureForm):
    title = StringField('Title', validators=[
        DataRequired(message='Title is required'),
        Length(min=5, max=200, message='Title must be 5-200 characters')
    ])
    duration = StringField('Duration', validators=[
        DataRequired(message='Duration is required'),
        Length(min=3, max=50, message='Duration must be 3-50 characters')
    ])
    difficulty = SelectField('Difficulty', choices=[
        ('easy', 'Easy'),
        ('moderate', 'Moderate'),
        ('challenging', 'Challenging'),
        ('expert', 'Expert')
    ], validators=[DataRequired(message='Please select difficulty')])
    price = IntegerField('Price (NPR)', validators=[
        DataRequired(message='Price is required'),
        NumberRange(min=1000, max=500000, message='Price must be between 1,000 and 500,000 NPR')
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(message='Description is required'),
        Length(min=50, max=2000, message='Description must be 50-2000 characters')
    ])
    highlights = TextAreaField('Highlights (one per line)', validators=[
        Optional(),
        Length(max=1000, message='Highlights too long')
    ])
    image = FileField('Tour Image', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'webp'], 'Only JPG, PNG, and WEBP images allowed')
    ])

class RentalForm(SecureForm):
    name = StringField('Bike Name', validators=[
        DataRequired(message='Bike name is required'),
        Length(min=3, max=100, message='Bike name must be 3-100 characters')
    ])
    category = SelectField('Category', choices=[
        ('standard', 'Standard'),
        ('classic', 'Classic'),
        ('adventure', 'Adventure'),
        ('touring', 'Touring')
    ], validators=[DataRequired(message='Please select category')])
    price_per_day = IntegerField('Price per Day (NPR)', validators=[
        DataRequired(message='Daily price is required'),
        NumberRange(min=500, max=50000, message='Daily price must be between 500-50,000 NPR')
    ])
    price_per_week = IntegerField('Price per Week (NPR)', validators=[
        DataRequired(message='Weekly price is required'),
        NumberRange(min=3000, max=300000, message='Weekly price must be between 3,000-300,000 NPR')
    ])
    description = TextAreaField('Description', validators=[
        DataRequired(message='Description is required'),
        Length(min=20, max=1000, message='Description must be 20-1000 characters')
    ])
    engine = StringField('Engine', validators=[
        DataRequired(message='Engine specification is required'),
        Length(min=5, max=100, message='Engine spec must be 5-100 characters')
    ])
    power = StringField('Power', validators=[
        DataRequired(message='Power specification is required'),
        Length(min=5, max=50, message='Power spec must be 5-50 characters')
    ])
    torque = StringField('Torque', validators=[
        DataRequired(message='Torque specification is required'),
        Length(min=5, max=50, message='Torque spec must be 5-50 characters')
    ])
    fuel_capacity = StringField('Fuel Capacity', validators=[
        DataRequired(message='Fuel capacity is required'),
        Length(min=5, max=50, message='Fuel capacity must be 5-50 characters')
    ])
    available = BooleanField('Available for Rent')
    image = FileField('Bike Image', validators=[
        Optional(),
        FileAllowed(['jpg', 'jpeg', 'png', 'webp'], 'Only JPG, PNG, and WEBP images allowed')
    ])

class StaffForm(SecureForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=50, message='Username must be 3-50 characters'),
        Regexp(r'^[a-zA-Z0-9_@.-]+$', message='Username contains invalid characters')
    ])
    name = StringField('Full Name', validators=[
        DataRequired(message='Name is required'),
        Length(min=2, max=100, message='Name must be 2-100 characters'),
        Regexp(r'^[a-zA-Z\s.-]+$', message='Name contains invalid characters')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=8, max=128, message='Password must be at least 8 characters'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]', 
               message='Password must contain uppercase, lowercase, number, and special character')
    ])
    role = SelectField('Role', choices=[
        ('staff', 'Staff'),
        ('admin', 'Admin')
    ], validators=[DataRequired(message='Please select role')])

    def validate_username(self, username):
        """Custom validation to check username uniqueness"""
        # This will be implemented in the route handler
        pass

class PasswordChangeForm(SecureForm):
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Current password is required')
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='New password is required'),
        Length(min=8, max=128, message='Password must be at least 8 characters'),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]', 
               message='Password must contain uppercase, lowercase, number, and special character')
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message='Please confirm your password')
    ])

    def validate_confirm_password(self, confirm_password):
        if self.new_password.data != confirm_password.data:
            raise ValidationError('Passwords do not match') 