from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Initialize database
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="customer")  # "customer" or "admin"

    def set_password(self, password):
        """Hashes the password and sets it"""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Checks the password against the hash"""
        return check_password_hash(self.password, password)

# Forms
class RegistrationForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm Password", 
                                     validators=[DataRequired(), EqualTo('password')])
    role = SelectField("Account Type", 
                       choices=[('customer', 'Customer'), ('admin', 'Admin')],
                       validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('customer', 'Customer')], validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")
    
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room_type = db.Column(db.String(50), nullable=False)
    check_in = db.Column(db.String(50), nullable=False)
    check_out = db.Column(db.String(50), nullable=False)
    special_requests = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    
class BookingForm(FlaskForm):
    room_type = SelectField('Room Type', choices=[
        ('standard', 'Standard Room'),
        ('deluxe', 'Deluxe Room'), 
        ('suite', 'Suite')
    ], validators=[DataRequired()])
    check_in = StringField('Check-In Date', validators=[DataRequired()])
    check_out = StringField('Check-Out Date', validators=[DataRequired()])
    special_requests = TextAreaField('Special Requests')
    submit = SubmitField('Confirm Booking')

# User Loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route("/")
def home():
    return render_template("landing.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():  # Validate the form
        name = form.name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data
        
        # Check if the user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists! Please log in.', 'danger')
            return redirect(url_for('login'))  # Redirect to login if email exists
        
        # Create a new user and hash the password
        new_user = User(name=name, email=email, role=role)
        new_user.set_password(password)  # Hash password here
        
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))  # Redirect to login after successful registration
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):  # Use the check_password method
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if user.role == 'admin':
                return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
            else:
                return redirect(next_page) if next_page else redirect(url_for('customer_dashboard'))
        flash('Login failed. Please check email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('customer_dashboard'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('customer_dashboard'))
    return render_template('admin_dashboard.html')

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    return render_template('customer_dashboard.html',)

@app.route('/book', methods=['GET', 'POST'])
@login_required
def book():
    form = BookingForm()  # You'll need to create this form class
    
    if form.validate_on_submit():
        # Process booking form data
        new_booking = Booking(
            user_id=current_user.id,
            room_type=form.room_type.data,
            check_in=form.check_in.data,
            check_out=form.check_out.data,
            special_requests=form.special_requests.data
        )
        db.session.add(new_booking)
        db.session.commit()
        flash('Your booking has been confirmed!', 'success')
        return redirect(url_for('customer_dashboard'))
    
    return render_template('book.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))  # Redirect to login page after logout

# Create the database tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
