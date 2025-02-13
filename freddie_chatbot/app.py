from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import json
import random
from azure.communication.email import EmailClient
from flask_mail import Mail, Message
import string
from sqlalchemy import func
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_dance.contrib.google import make_google_blueprint, google
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer
import logging
import secrets
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests 
import logging
from logging.handlers import RotatingFileHandler



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'f96aa93eba014e3eae4c27808b3cfa7e'
app.config['PREFERRED_URL_SCHEME'] = 'https'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Set up logging to a file with rotation
handler = RotatingFileHandler('/var/log/flask_app.log', maxBytes=10000000, backupCount=3)
handler.setLevel(logging.DEBUG)  # You can set this to ERROR or DEBUG depending on your needs
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)


# Google OAuth Configurations
app.config['GOOGLE_CLIENT_ID'] = '29838627644-75eskj0hmv98pk5khle6gm3ohcgm9a8h.apps.googleusercontent.com'
app.config['GOOGLE_CLIENT_SECRET'] = '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'
app.config['GOOGLE_DISCOVERY_URL'] = 'https://accounts.google.com/.well-known/openid-configuration'

# OAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={'scope': 'openid email profile'}
)

# Function to generate an 8-character random password
def generate_random_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))


@app.route('/auth/google', methods=['POST'])
def auth_google_post():
    try:
        # Get the incoming JSON data
        data = request.get_json()
        if not data:
            app.logger.error("No data received in the request.")
            return jsonify({'success': False, 'message': 'No data received in the request'}), 400

        app.logger.info(f"Received data: {data}")
        google_token = data.get('credential')
        if not google_token:
            app.logger.error("Google token missing from request data.")
            return jsonify({'success': False, 'message': 'Google token missing from request data'}), 400

        # Verify the token with Google
        try:
            google_request = google_requests.Request()  # Use renamed import
            idinfo = id_token.verify_oauth2_token(google_token, google_request, app.config['GOOGLE_CLIENT_ID'])
            app.logger.info(f"Validated ID Token: {idinfo}")
        except ValueError as ve:
            app.logger.error(f"Token verification failed: {ve}")
            return jsonify({'success': False, 'message': 'Invalid Google token'}), 400

        # Extract user info
        email = idinfo.get('email')
        firstname = idinfo.get('given_name', 'GoogleUser')
        lastname = idinfo.get('family_name', '')
        username = idinfo.get('name', email.split('@')[0])

        # Ensure email is verified
        if not idinfo.get('email_verified'):
            app.logger.error("Email not verified.")
            return jsonify({'success': False, 'message': 'Email not verified'}), 400

        # Check if user exists in the database
        existing_user = User.query.filter_by(email=email).first()
        # Generate customer number
        cust_no = generate_customer_no(firstname, lastname)

        if existing_user:
            existing_user.firstname = firstname
            existing_user.lastname = lastname
            existing_user.username = username
            db.session.commit()
            login_user(existing_user)

            # Log the login history
            login_history = LoginHistory(
                cust_no=existing_user.cust_no,
                login_time=datetime.utcnow()
            )
            db.session.add(login_history)
            db.session.commit()

            return jsonify({'success': True, 'message': 'Logged in successfully'})
        else:
            # Create new user
            new_user = User(
                cust_no=cust_no,
                firstname=firstname,
                lastname=lastname,
                username=username,
                email=email,
                password=generate_password_hash(generate_random_password(8)),  # Use shorter password
                role='User'
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            # Log the login history for the new user
            login_history = LoginHistory(
                cust_no=new_user.cust_no,
                login_time=datetime.utcnow()
            )
            db.session.add(login_history)
            db.session.commit()

            return jsonify({'success': True, 'message': 'New user created and logged in successfully'})

    except Exception as e:
        app.logger.error(f"Error during Google OAuth login: {e}")
        return jsonify({'success': False, 'message': 'Google login failed'}), 400

@app.route('/agcallback')
def auth_google_callback():
    """Google Callback Route"""
    try:
        token = google.authorize_access_token()
        nonce = session.pop('nonce', None)  # Retrieve and remove the nonce from session
        user_info = google.parse_id_token(token, nonce=nonce)  # Pass nonce for validation
        # Process the user_info as needed
        session['user'] = user_info  # Store user info in session
        return f"Hello, {user_info['name']}! You have successfully logged in with Google."
    except Exception as e:
        app.logger.error(f"Error during Google OAuth callback: {e}")
        return redirect(url_for('login'))  # Redirect back to login on failure




# Define the Coach model
class Coach(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    experience = db.Column(db.Text, nullable=False)
    specialization = db.Column(db.String(50), nullable=False)
    qualifications = db.Column(db.Text, nullable=False)
    availability = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    languages = db.Column(db.String(100), nullable=False)
    terms = db.Column(db.Boolean, nullable=False)
    preferred_method = db.Column(db.String(100), nullable=False)
    twitter = db.Column(db.String(100), nullable=True)
    facebook = db.Column(db.String(100), nullable=True)
    newsletter = db.Column(db.Boolean, nullable=True)
    referral = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="Coach")
    # Establish relationship with the Client model
    clients = relationship("Client", back_populates="coach")

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    cust_no = db.Column(db.String(10), unique=True, nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="User")
    has_agreed = db.Column(db.Boolean, default=False)  # Flag to check agreement

# Relationship with UserDetails, specifying which foreign key to use
    user_details = db.relationship('UserDetails', backref='user_ref', uselist=False, foreign_keys='UserDetails.user_id')


    
    # Relationship with UserAgreement (one-to-many, because one user can have multiple agreements over time)
    agreements = db.relationship('UserAgreement', backref='user_agreements', lazy=True)

class UserDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to User's primary key
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), unique=True, nullable=False)  # Link to User's cust_no

    dob = db.Column(db.String(20))  # Date of Birth
    interests_hobbies = db.Column(db.String(200))  # Combined interests and hobbies
    age_group = db.Column(db.String(20))  # Dropdown: 16-18, 19-30, etc.
    seniority = db.Column(db.String(50))  # Dropdown: Recent Graduate, Executive, etc.
    education_category = db.Column(db.String(50))  # Dropdown: 12 Years, 13-16 Years, etc.
    income = db.Column(db.String(20))  # Dropdown: Less than 5 lakhs, etc.
    marital_status = db.Column(db.String(20))  # Dropdown: Married, Single, Divorced, etc.
    country = db.Column(db.String(50))
    state = db.Column(db.String(50))
    gender = db.Column(db.String(10))  # Dropdown: Male, Female, Others
    occupation = db.Column(db.String(50))  # Dropdown: Industrialist, IT Professional, etc.

    # Link to User model through user_id, using the distinct backref name
    user = db.relationship('User', backref='user_details_ref', foreign_keys=[user_id], uselist=False)




    
class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)


# Define the Feedback model
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comments = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Define the UserSelection model
class UserSelection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_no = db.Column(db.String(10), unique=True, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    coach = db.Column(db.String(100), nullable=False)
    topic = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Define the Question model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Define the Notification model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    generated_id = db.Column(db.String(100), nullable=True)
    generated_password = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), nullable=False)
    question = db.Column(db.String(500), nullable=False)
    answer = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), nullable=False)
    topic = db.Column(db.String(500), unique=True, nullable=False)

    def __repr__(self):
        return f"<Topic {self.topic}>"

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    topic = db.Column(db.String(500), db.ForeignKey('topic.topic'), nullable=False)
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), nullable=False)
    user_message = db.Column(db.String(500), nullable=False)
    bot_response = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    topic_rel = db.relationship('Topic', backref=db.backref('conversations', lazy=True), foreign_keys=[topic])
    user_rel = db.relationship('User', backref=db.backref('conversations', lazy=True))

class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), nullable=False)
    goal1 = db.Column(db.String(255), nullable=False)
    goal2 = db.Column(db.String(255), nullable=True)
    goal3 = db.Column(db.String(255), nullable=True)

class Category(db.Model):
   

    id = db.Column(db.Integer, primary_key=True)  # Primary key for the Category
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), nullable=False)  # Foreign key referencing user
    name = db.Column(db.String(100), nullable=False)  # Name of the category
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=False)  # Foreign key referencing topic

class Client(db.Model):
    __tablename__ = 'clients'  # Optional, but good practice

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=True)
    frequency = db.Column(db.String(50), nullable=False)

    # Foreign key to link Client to Coach
    coach_id = db.Column(db.Integer, db.ForeignKey('coach.id'), nullable=False)  # Adjust based on your coach model name

    # Establish relationship with the Coach model
    coach = relationship("Coach", back_populates="clients")

class UserAgreement(db.Model):
    __tablename__ = 'user_agreements'

    id = db.Column(db.Integer, primary_key=True)
    cust_no = db.Column(db.String(10), db.ForeignKey('user.cust_no'), nullable=False)  # Foreign key to User table
    agreed_on = db.Column(db.DateTime, nullable=False, default=db.func.now())
    terms_version = db.Column(db.String(50), nullable=False)
    
    # The relationship is implicitly established with the User model using the backref 'user_agreements'
    user = db.relationship('User', backref=db.backref('user_agreements', lazy=True))  # One-to-many, user can have multiple agreements


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        return user
    return Coach.query.get(int(user_id))

def generate_customer_no(firstname, lastname):
    prefix = firstname[:2].lower() + lastname[:2].lower()
    while True:
        suffix = ''.join(random.choices('0123456789', k=4))
        cust_no = prefix + suffix
        if not User.query.filter_by(cust_no=cust_no).first():
            return cust_no

DEPLOYMENT_URI = "https://Mistral-large-faekz-serverless.eastus2.inference.ai.azure.com/v1/chat/completions"
TOKEN = "Gc9p7keKdHo0IXptpg0grOfgz3Ei984a"
headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Configure mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'aishwaryaammu0102@gmail.com'  # Your email
app.config['MAIL_PASSWORD'] = 'mdhx urwp vamm jwjb'  # Your app password

mail = Mail(app)

# Azure Email Client Configuration
AZURE_CONNECTION_STRING = "endpoint=https://freddie-email.india.communication.azure.com/;accesskey=Czr5YUAXaL6ngxsZRg8K0TJ04MA6OOc7xIJNJ4HIXYtgKVqnogqbJQQJ99AHACULyCppJDEQAAAAAZCSvvrg"
SENDER_EMAIL = "DoNotReply@eduvitz.co.in"  # Replace with your verified sender domain


# Create the database tables
with app.app_context():
    db.create_all()


# Home route
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/coach_dashboard')
@login_required
def coach_dashboard():
    coach_id = current_user.id  # Assuming the logged-in coach's ID is stored in current_user
    coach_full_name = get_coach_full_name(coach_id)

    if coach_full_name is None:
        flash('Coach not found.', 'error')
        return redirect(url_for('login'))

    # Extract the first letter of the coach's full name
    coach_initial = coach_full_name[0].upper()  # Get the first letter and convert it to uppercase

    return render_template('coach_dashboard.html', coach_initial=coach_initial)

@app.route('/home', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/analytics_report', methods=['GET'])
def analytics_report():
    return render_template('analytics_report.html')



def get_user_full_name(user_id):
    user = User.query.get(user_id)  # Assuming you have a User model
    if user:
        return user.firstname  # Adjust this according to your User model's attribute
    return None

def get_coach_full_name(coach_id):
    coach = Coach.query.get(coach_id)
    if coach:
        return coach.full_name
    return None



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')  # Use `.get()` for safer key access
        password = request.form.get('password')

        if not email or not password:  # Handle missing fields
            flash('Email and password are required.', 'error')
            return render_template('login.html')

        # Check if the email belongs to a Coach
        coach = Coach.query.filter_by(email=email).first()
        if coach and password == coach.password:
            login_user(coach)
            return redirect(url_for('coach_dashboard'))

        # Check if the email belongs to a User
        user = User.query.filter_by(email=email).first()
        if user and password == user.password:
            login_user(user)
            
            # Log the login history
            login_history = LoginHistory(
                cust_no=user.cust_no,
                login_time=datetime.utcnow()
            )
            db.session.add(login_history)
            db.session.commit()

            return redirect(url_for('user_dashboard'))

        # If no user or invalid credentials
        flash('Invalid email or password', 'error')

    # Ensure a response is returned in all cases
    return render_template('login.html')

# User dashboard route
# Function to get the user's full name or username
def get_user_full_name(user_id):
    user = User.query.get(user_id)  # Query the user from the database
    if user:
        return user.username  # Assuming your User model has a `username` field instead of `full_name`
    return None

@app.route('/user_dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    user_id = current_user.id  # Get the logged-in user's ID from Flask-Login

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        coach = request.form.get('coach')
        topic = request.form.get('topic')

        # Create a new UserSelection record
        new_selection = UserSelection(
            username=username,
            email=email,
            coach=coach,
            topic=topic,
            user_id=user_id
        )
        db.session.add(new_selection)

        try:
            db.session.commit()
            flash('Selection submitted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {e}', 'error')

        return redirect(url_for('user_dashboard'))

    # Check if the user's profile is complete
    user_profile = db.session.query(UserDetails).filter_by(user_id=user_id).first()
    is_profile_complete = user_profile is not None

    # Fetch the username of the user
    username = get_user_full_name(user_id)

    if username is None:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    # Render the dashboard template with the `is_profile_complete` variable
    return render_template(
        'user_dashboard.html',
        username=username,
        is_profile_complete=is_profile_complete  # Pass the flag to the template
    )


@app.route('/select_role', methods=['GET', 'POST'])
def select_role():
    if request.method == 'POST':
        role = request.form['role']
        if role == 'User':
            return redirect(url_for('register_user'))
        elif role == 'Coach':
            return redirect(url_for('register_coach'))
        else:
            flash('Invalid role selected', 'error')

    return render_template('select_role.html')



@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"status": "error", "message": "Username already exists"}), 400

        # Generate customer number
        cust_no = generate_customer_no(firstname, lastname)

        # Create a new User record
        new_user = User(
            cust_no=cust_no,
            firstname=firstname,
            lastname=lastname,
            username=username,
            email=email,
            password=password
        )

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return jsonify({"status": "success", "redirect_url": url_for('login')})

    return render_template('register_user.html')  # Render the registration page for GET requests

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if current_user.role != 'User':  # Restrict to users with the role 'User'
        flash('Please log in as a user to view this page.', 'error')
        return redirect(url_for('login'))

    # Fetch the user and user details
    user = User.query.get(current_user.id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('login'))

    user_details = UserDetails.query.filter_by(cust_no=user.cust_no).first()

    if request.method == 'POST':
        # Fetch form data
        dob = request.form.get('dob')
        interests_hobbies = request.form.get('interests_hobbies')
        age_group = request.form.get('age_group')
        seniority = request.form.get('seniority')
        education_category = request.form.get('education_category')
        income = request.form.get('income')
        marital_status = request.form.get('marital_status')
        country = request.form.get('country')
        state = request.form.get('state')
        gender = request.form.get('gender')
        occupation = request.form.get('occupation')

        if user_details:
            # Update existing record
            user_details.dob = dob
            user_details.interests_hobbies = interests_hobbies
            user_details.age_group = age_group
            user_details.seniority = seniority
            user_details.education_category = education_category
            user_details.income = income
            user_details.marital_status = marital_status
            user_details.country = country
            user_details.state = state
            user_details.gender = gender
            user_details.occupation = occupation
        else:
            # Create new record
            user_details = UserDetails(
                user_id=user.id,
                cust_no=user.cust_no,
                dob=dob,
                interests_hobbies=interests_hobbies,
                age_group=age_group,
                seniority=seniority,
                education_category=education_category,
                income=income,
                marital_status=marital_status,
                country=country,
                state=state,
                gender=gender,
                occupation=occupation,
            )
            db.session.add(user_details)

        db.session.commit()
        flash("Profile updated successfully!")
        return redirect(url_for('user_dashboard'))

    return render_template('edit_profile.html', user=user, user_details=user_details)







@app.route('/profile')
@login_required
def profile():
    user = User.query.get(current_user.id)
    user_details = UserDetails.query.filter_by(cust_no=user.cust_no).first()  # Fetch extended profile details

    return render_template('profile.html', user=user, user_details=user_details)






# Coach Registration Route
@app.route('/register_coach', methods=['GET', 'POST'])
def register_coach():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        experience = request.form['experience']
        specialization = request.form['specialization']
        qualifications = request.form['qualifications']
        availability = request.form['availability']
        location = request.form['location']
        gender = request.form['gender']
        languages = request.form['languages']
        terms = request.form.get('terms') == 'on'
        preferred_method = request.form['preferred_method']
        twitter = request.form['twitter']
        facebook = request.form['facebook']
        newsletter = request.form.get('newsletter') == 'on'
        referral = request.form['referral']

        new_coach = Coach(
            full_name=full_name,
            email=email,
            password=password,
            phone=phone,
            experience=experience,
            specialization=specialization,
            qualifications=qualifications,
            availability=availability,
            location=location,
            gender=gender,
            languages=languages,
            terms=terms,
            preferred_method=preferred_method,
            twitter=twitter,
            facebook=facebook,
            newsletter=newsletter,
            referral=referral
        )

        db.session.add(new_coach)
        db.session.commit()
        flash('Coach registered successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('register_coach.html')

# Feedback route
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        user_id = session.get('user_id')
        rating = request.form.get('rating')
        comments = request.form.get('comments')

        feedback_entry = Feedback(user_id=user_id, rating=rating, comments=comments)
        db.session.add(feedback_entry)
        db.session.commit()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('feedback.html')

# Questions route
@app.route('/questions', methods=['GET', 'POST'])
def questions():
    if request.method == 'POST':
        question_text = request.form.get('question_text')
        category = request.form.get('category')
        difficulty = request.form.get('difficulty')

        new_question = Question(question_text=question_text, category=category, difficulty=difficulty)
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!', 'success')

    questions = Question.query.all()
    return render_template('questions.html', questions=questions)


# Theme route
@app.route('/theme', methods=['GET'])
def theme():
    return render_template('theme.html')  # Create this HTML file to design the theme page







# Coach Profile Route
@app.route('/coach_profile', methods=['GET'])
@login_required
def coach_profile():
    if current_user.role == 'Coach':  # Check the role stored in the User model
        coach = Coach.query.get(current_user.id)
        if coach:
            return render_template('coach_profile.html', coach=coach)
    flash('Please log in as a coach to view this page.', 'error')
    return redirect(url_for('login'))




# Coach & Topic Selection Route
@app.route('/coach_topic_selection', methods=['GET'])
@login_required
def coach_topic_selection():
    if current_user.role == 'User':  # Check the role stored in the User model
        user = User.query.get(current_user.id)
        if user:
            try:
                username = user.username if user.username else '?'  # Fetch the username
            except AttributeError as e:
                print(f"Error: {e}")
                return "User object does not have a username attribute.", 500
            return render_template('coach_topic_selection.html', username=username)
        else:
            return redirect(url_for('login'))  # Redirect to login if user not found
    return redirect(url_for('login'))  # Redirect to login if not logged in

# Notifications route
@app.route('/notifications', methods=['GET'])
@login_required
def notifications():
    # Check if the current user has the role 'User'
    if current_user.role == 'User':
        user_full_name = current_user.firstname  # Get the user's full name from the current_user object

        if user_full_name:
            return render_template('notifications.html', user_name=user_full_name[0])  # Pass the first letter of the full name
        else:
            flash('User not found in the database.', 'error')
            return redirect(url_for('login'))
    else:
        flash('Access denied. Only users can view this page.', 'error')
        return redirect(url_for('login'))
# Chatbot route
@app.route('/chatbot', methods=['GET'])
def chatbot():
    if 'role' in session and session['role'] == 'User':
        user_id = session.get('user_id')  # Get the user ID from the session
        if user_id:
            # Fetch the user's full name from the database
            user_full_name = get_user_full_name(user_id)  # Replace with your actual DB call
            
            if user_full_name:
                # Extract the first letter of the user's full name
                first_letter = user_full_name[0][0].upper()  # Assuming user_full_name[0] is the full name
                return render_template('chatbot.html', user_name=first_letter)
            else:
                flash('User not found in the database.', 'error')
                return redirect(url_for('login'))
        else:
            flash('User ID not found in the session.', 'error')
            return redirect(url_for('login'))
    flash('Please log in to view this page.', 'error')
    return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/chatbot_without_coach')
@login_required  # Ensure user is logged in
def chatbot_without_coach():
    if current_user.has_agreed:
        return render_template('chatbot_without_coach.html', show_agreement=False)
    else:
        return render_template('chatbot_without_coach.html', show_agreement=True)


@app.route('/get_chat_history', methods=['POST'])
@login_required
def get_chat_history():
    data = request.json
    cust_no = current_user.cust_no  # Get the current user's customer number
    topic = data.get('topic')  # Get the topic from the request data

    # Fetch the category for the current topic
    current_category = get_category_for_topic(topic)

    # Fetch the category of the last topic for the user
    last_topic = Topic.query.filter_by(cust_no=cust_no).order_by(Topic.id.desc()).first()
    
    if last_topic:
        last_category = get_category_for_topic(last_topic.topic)
    else:
        last_category = None  # No previous topics

    # Determine if categories match
    if current_category == last_category:
        # Fetch the total number of user messages for the given topic
        user_message_count = Conversation.query.filter_by(cust_no=cust_no, topic=last_topic.topic).count() if last_topic else 0
        bot_response_counter = Conversation.query.filter_by(cust_no=cust_no, topic=last_topic.topic).count() if last_topic else 0
        # Check if the user has reached the maximum number of messages
        reached_max_limit = user_message_count >= 9

        # Fetch the last 2 conversations based on topic and customer number
        conversations = Conversation.query.filter_by(cust_no=cust_no, topic=last_topic.topic).order_by(Conversation.id.desc()).limit(2).all()

        # Reverse the conversations to display them in the correct chronological order
        conversations.reverse()

        # Prepare the chat history data for the frontend
        chat_history = []
        for conv in conversations:
            chat_history.append({'role': 'user', 'content': conv.user_message})
            chat_history.append({'role': 'assistant', 'content': conv.bot_response})

        return jsonify({
            'chat_history': chat_history,
            'reached_max_limit': reached_max_limit,
            'user_message_count': user_message_count,
            'bot_response_counter':bot_response_counter
        })
    else:
        # Different category, no history to fetch
        return jsonify({
            'chat_history': [],
            'reached_max_limit': False,
            'user_message_count': 0,
            'bot_response_counter':0
        })



@app.route('/get_bot_response', methods=['POST'])
def get_bot_response():
    if not current_user.is_authenticated:
        return jsonify({"error": "User is not authenticated"}), 401
    
    # Get user input
    user_input = request.json.get('user_input')
    if not user_input:
        return jsonify({"error": "User input is missing"}), 400
    
    cust_no = current_user.cust_no

    # Get the latest topic for the user
    latest_topic = Topic.query.filter_by(cust_no=cust_no).order_by(Topic.id.desc()).first()
    
    if latest_topic:
        # Fetch conversation history for the specific topic
        conversation_history = Conversation.query.filter_by(topic=latest_topic.topic).order_by(Conversation.created_at).all()
    else:
        # If no latest topic, initialize an empty conversation history
        conversation_history = []

    # Format the conversation history for the bot
    formatted_history = []
    if conversation_history:
        formatted_history = [{"role": "user", "content": convo.user_message} if i % 2 == 0 else {"role": "assistant", "content": convo.bot_response} for i, convo in enumerate(conversation_history)]
    
    # Add the current user input to the history
    formatted_history.append({"role": "user", "content": user_input})

    # Get bot response
    try:
        bot_response = get_bot_response_from_mistral(formatted_history, latest_topic.topic if latest_topic else "")
    except Exception as e:
        print("Error getting response from Mistral:", e)
        return jsonify({"error": "Failed to get response from bot"}), 500

    # Save user response and bot response
    save_user_response(cust_no, user_input, bot_response)  # Ensure this function matches your definition

    return jsonify({'bot_response': bot_response})


# Function to read the prompt from a text file
def read_prompt_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            print("Prompt read successfully.")  # Confirmation message
            return file.read().strip()
    except FileNotFoundError:
        raise Exception(f"Error: The prompt file {file_path} was not found.")

# Function to get the appropriate prompt based on email domain
def get_prompt_based_on_email(email):
    if email.endswith('@intalage.com'):
        return read_prompt_from_file('//home//sumaiya//freddie//freddie_chatbot//prompts//intalage_prompt.txt')  # Path for @intalage.com users
    else:
        return read_prompt_from_file('//home//sumaiya//freddie//freddie_chatbot//prompts//chpr01.txt')  # Path for other users

def get_bot_response_from_mistral(conversation_history, topic):
     # Get the logged-in user's email
    email = current_user.email
    
    # Get the system message prompt based on the user's email domain
    system_message = get_prompt_based_on_email(email)
    if topic:
        system_message += f" The current topic of discussion is: {topic}"

    payload = {
        "messages": [
            {"role": "system", "content": system_message}
        ] + conversation_history,
        "temperature": 0.8,
        "max_tokens": 512
    }
    json_payload = json.dumps(payload)
    response = requests.post(DEPLOYMENT_URI, headers=headers, data=json_payload)
    if response.status_code == 200:
        try:
            return response.json()["choices"][0]["message"]["content"]
        except KeyError:
            print("Unexpected response format:")
            print(response.json())
            return "Error: Unexpected response format"
    else:
        return f"Error: {response.status_code}, {response.text}"



def save_user_response(cust_no, question, answer):
    # Save the user response
    user_response = UserResponse(cust_no=cust_no, question=question, answer=answer)
    db.session.add(user_response)
    
    # Retrieve the latest topic for the user
    latest_topic = Topic.query.filter_by(cust_no=cust_no).order_by(Topic.id.desc()).first()
    
    if latest_topic:
        # Save the conversation to the Conversation table
        conversation = Conversation(topic=latest_topic.topic, cust_no=cust_no, user_message=question, bot_response=answer)
        db.session.add(conversation)
    
    db.session.commit()  # Commit the response and conversation to ensure they are saved in the database

    
    
@app.route('/save_topic', methods=['POST'])
def save_topic():
    data = request.json  # Get JSON data from request body
    
    cust_no = current_user.cust_no
    topic = data.get('topic')
    
    # Save the topic
    topic_response = Topic(cust_no=cust_no, topic=topic)
    db.session.add(topic_response)
    db.session.commit()
    
    # Derive a category for the new topic
    derived_category = derive_category(topic)
    
    # Save the category
    if derived_category:
        category_response = Category(cust_no=cust_no,name=derived_category, topic_id=topic_response.id)
        db.session.add(category_response)
        db.session.commit()
    
    return jsonify({'message': 'Topic saved and categorized successfully.'})

def get_category_for_topic(topic):
    # Assuming you have a method to derive the category based on the topic
    category_record = Category.query.filter_by(topic_id=Topic.query.filter_by(topic=topic).first().id).first()
    return category_record.name if category_record else None

def derive_category(topic):
    # Create a prompt to send to Mistral
    prompt = (f"Categorize the topic '{topic}' into one of the following categories: "
              "Personal Development, Career Coaching, Health and Wellness, "
              "Relationships, Financial Wellness, Mindfulness and Stress Management. "
              "Please provide only one category.")

    payload = {
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant that categorizes topics."
            },
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 50,
        "stop": None
    }
    
    # Convert the payload to JSON
    json_payload = json.dumps(payload)

    # Make the POST request to Mistral
    response = requests.post(DEPLOYMENT_URI, headers=headers, data=json_payload)
    
    # Check the response status
    if response.status_code == 200:
        try:
            # Extract the response content
            content = response.json()["choices"][0]["message"]["content"].strip()

            # Use regex to find only one of the specified categories
            categories = [
                "Personal Development", 
                "Career Coaching", 
                "Health and Wellness", 
                "Relationships", 
                "Financial Wellness", 
                "Mindfulness and Stress Management"
            ]
            # Check which category is mentioned in the content
            for category in categories:
                if category in content:
                    return category  # Return the first matched category

            return "Category not found"  # In case none match, return this
        except KeyError:
            print("Unexpected response format:")
            print(response.json())
            return None
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None  # Or handle the error accordingly

@app.route('/derive_topic', methods=['POST'])
def derive_topic():
    data = request.json
    responses = data.get('responses')
    
    if not responses or len(responses) != 2:
        return jsonify({'error': 'Invalid input'}), 400
    
    derived_topic = get_derived_topic(responses)
    
    return jsonify({'topic': derived_topic})

def get_derived_topic(responses):
    prompt = f"Create a meaningful topic based on these two responses:\n1. {responses[0]}\n2. {responses[1]}\n\nTopic:"
    payload = {
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant that creates meaningful topics based on user responses."
            },
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.7,
        "max_tokens": 50,
        "stop": None
    }
    json_payload = json.dumps(payload)
    response = requests.post(DEPLOYMENT_URI, headers=headers, data=json_payload)
    if response.status_code == 200:
        try:
            return response.json()["choices"][0]["message"]["content"]
        except KeyError:
            print("Unexpected response format:")
            print(response.json())
            return "Error: Unexpected response format"
    else:
        return f"Error: {response.status_code}, {response.text}"

@app.route('/get_existing_topics', methods=['POST'])
@login_required
def get_topics():
    # Get distinct topics the current user has discussed
    distinct_topics = db.session.query(Topic.topic).filter_by(cust_no=current_user.cust_no).distinct().all()

    # If no topics are found
    if not distinct_topics:
        return jsonify({"message": "You have no previous topics."})
    
    # Flatten the result from [(topic1,), (topic2,), ...] to [topic1, topic2, ...]
    topics_list = [topic[0] for topic in distinct_topics]
    
    return jsonify(topics_list)

@app.route('/save_goals', methods=['POST'])
def save_goals():
    data = request.get_json()
    cust_no = data.get('cust_no')
    goal1 = data.get('goal1')
    goal2 = data.get('goal2')
    goal3 = data.get('goal3')
    
    # Check if goal1 is "hi", if it is, do not save to the database
    if goal1.lower() == "hi":
        return jsonify({"message": "Goal 1 cannot be 'hi'. Please provide a valid goal."}), 400
    

    # Save the goals in the database
    new_goals = Goal(cust_no=cust_no, goal1=goal1, goal2=goal2,goal3=goal3 )
    db.session.add(new_goals)
    db.session.commit()

    return jsonify({"message": "Goals saved successfully"}), 200

@app.route('/check_goals/<cust_no>', methods=['GET'])
def check_goals(cust_no):
    # Retrieve the user's goals from the database
    user_goal = Goal.query.filter_by(cust_no=cust_no).first()
    
    if user_goal:
        # Check if goal1 is set, and if so, then the user has goals
        goals_exist = {
            "goal1": user_goal.goal1 is not None
        }
        
        # If goal1 exists, check if goal2 or goal3 are set
        if user_goal.goal1 is not None:
            goals_exist["goal2"] = user_goal.goal2 is not None
            goals_exist["goal3"] = user_goal.goal3 is not None
        
        return jsonify({"goals_exist": goals_exist}), 200
    else:
        # If no goals are set at all (i.e., goal1 is None)
        return jsonify({"goals_exist": {"goal1": False, "goal2": False, "goal3": False}}), 200


@app.route('/get_response_count/<string:cust_no>/<string:topic>', methods=['GET'])
def get_response_count(cust_no, topic):
    try:
        # Query the count of conversations for the given cust_no and topic
        conversation_count = db.session.query(Conversation).filter_by(cust_no=cust_no, topic=topic).count()
        
        return jsonify({"count": conversation_count}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



def send_email(to_email, subject, plain_text_body, html_body): 
    try:
        connection_string = "endpoint=https://freddie-email.india.communication.azure.com/;accesskey=Czr5YUAXaL6ngxsZRg8K0TJ04MA6OOc7xIJNJ4HIXYtgKVqnogqbJQQJ99AHACULyCppJDEQAAAAAZCSvvrg"  # Add your connection string here
        client = EmailClient.from_connection_string(connection_string)

        # Initialize the email message
        message = {
            "senderAddress": "DoNotReply@eduvitz.co.in",  # Update with your domain
            "recipients": {
                "to": [{"address": to_email}],
                "cc": []  # Initialize CC as an empty list
            },
            "content": {
                "subject": subject,
                "plainText": plain_text_body,
                "html": html_body
            },
        }   
        print("message:",message)

        # Check if the recipient email ends with @intalage.com
        if to_email.endswith("@intalage.com"):
            # Add Nasreen as a CC recipient
            message["recipients"]["cc"].append({"address": "nasreen@intalage.com"})

        # Send the email
        poller = client.begin_send(message)
        result = poller.result()
        print("Message sent successfully!")

    except Exception as ex:
        print(f"Failed to send email: {ex}")

# Flask route to handle /send_email
@app.route('/send_email', methods=['POST'])
def email_handler():
    try:
        # Get the current user's email
        to_email = current_user.email
        print("email id:",to_email)

        # Get the latest login session
        login_history = LoginHistory.query.filter_by(cust_no=current_user.cust_no).order_by(LoginHistory.login_time.desc()).first()
        print("login history",login_history)
        if not login_history:
            return jsonify({"error": "No login history found"}), 400

        # Fetch conversations after the latest login
        conversations = Conversation.query.filter(
            Conversation.cust_no == current_user.cust_no,
            Conversation.created_at >= login_history.login_time
        ).all()
        print("conversation:",conversations)

        # Organize conversations by topic
        conversations_by_topic = {}
        for convo in conversations:
            if convo.topic not in conversations_by_topic:
                conversations_by_topic[convo.topic] = []
            conversations_by_topic[convo.topic].append(convo)

        # Format the conversations into a transcript
        transcript = "Freddie AI Coach - Your Chat Transcript\n\n"
        for topic, convos in conversations_by_topic.items():
            transcript += f"Topic: {topic}\n"
            for convo in convos:
                # Format created_at to remove milliseconds
                formatted_time = convo.created_at.strftime("%Y-%m-%d %H:%M:%S")
                transcript += f"{current_user.username}: {convo.user_message}\n"
                transcript += f"Freddie: {convo.bot_response}\n"
                transcript += f"Time: {formatted_time}\n"
            transcript += "\n"  # Add a blank line between topics

        # Prepare the email content
        subject = "Your Chat Transcript from Freddie AI Coach"
        plain_text_body = transcript
        html_body = """
        <h1>Freddie AI Coach</h1>
        <h2>Your Chat Transcript</h2>
        """
        for topic, convos in conversations_by_topic.items():
            html_body += f"<h3>Topic: {topic}</h3>"
            for convo in convos:
                # Format created_at to remove milliseconds
                formatted_time = convo.created_at.strftime("%Y-%m-%d %H:%M:%S")
                html_body += f"<p><strong>{current_user.username}:</strong> {convo.user_message}</p>"
                html_body += f"<p><strong>Freddie:</strong> {convo.bot_response}</p>"
                html_body += f"<p><em>Time: {formatted_time}</em></p>"
            html_body += "<hr>"  # Add a horizontal line between topics

        # Send the email
        send_email(to_email, subject, plain_text_body, html_body)

        # Return a success message
        return jsonify({"status": "Email sent successfully"}), 200

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({"error": str(e)}), 500

    
@app.route('/check_topic_limit/<string:cust_no>')
def check_topic_limit(cust_no):
    # Query to count distinct topics for the specified customer
    topic_count = db.session.query(func.count(Conversation.topic.distinct())).filter_by(cust_no=cust_no).scalar()
    
    return jsonify({"topic_count": topic_count})

@app.route('/add_client', methods=['GET', 'POST'])
def add_client():
    if request.method == 'POST':
        # Handle adding a new client
        data = request.get_json()
        coach_id = current_user.id  # Adjust this as needed

        # Check if start_date is present
        if not data.get('start_date'):
            return jsonify({"success": False, "message": "start_date is required."}), 400

        # Convert start_date and end_date to date objects
        try:
            start_date = datetime.strptime(data.get('start_date'), '%Y-%m-%d').date()
        except ValueError:
            return jsonify({"success": False, "message": "Invalid start_date format. Use YYYY-MM-DD."}), 400

        end_date = None
        if data.get('end_date'):
            try:
                end_date = datetime.strptime(data.get('end_date'), '%Y-%m-%d').date()
            except ValueError:
                return jsonify({"success": False, "message": "Invalid end_date format. Use YYYY-MM-DD."}), 400
        
        # Generate a random password
        password = generate_random_password()

        # Create a new client instance
        new_client = Client(
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            email=data.get('email'),
            start_date=start_date,
            end_date=end_date,
            frequency=data.get('frequency'),
            coach_id=coach_id  # Associate with the current coach
        )

        # Add the new client to the session and commit
        db.session.add(new_client)
        db.session.commit()

        # Send the email with the generated password
        try:
            connection_string = "endpoint=https://freddie-email.india.communication.azure.com/;accesskey=Czr5YUAXaL6ngxsZRg8K0TJ04MA6OOc7xIJNJ4HIXYtgKVqnogqbJQQJ99AHACULyCppJDEQAAAAAZCSvvrg"
            client = EmailClient.from_connection_string(connection_string)

            message = {
                "senderAddress": "DoNotReply@eduvitz.co.in",  # Replace with your sender email
                "recipients": {
                    "to": [{"address": new_client.email}]
                },
                "content": {
                    "subject": "Your Freddie Login Details",
                    "plainText": f"Hello {new_client.first_name},\n\n"
                                 f"Welcome to Freddie, your intelligent life coach!\n\n"
                                 f"Here are your login details:\n"
                                 f"Email: {new_client.email}\n"
                                 f"Password: {password}\n\n"
                                 f"Please use these credentials to log in to Freddie and start your coaching journey.\n\n"
                                 f"Best regards,\nThe Freddie Team",
                    "html": f"""
                    <html>
                        <body>
                            <h1>Hello {new_client.first_name},</h1>
                            <p>Welcome to Freddie, your intelligent life coach!</p>
                            <p>Here are your login details:</p>
                            <ul>
                                <li><strong>Email:</strong> {new_client.email}</li>
                                <li><strong>Password:</strong> {password}</li>
                            </ul>
                            <p>Please use these credentials to log in to Freddie and start your coaching journey.</p>
                            <p>Best regards, <br>The Freddie Team</p>
                        </body>
                    </html>"""
                },
            }

            poller = client.begin_send(message)
            result = poller.result()
            print("Message sent: ")

        except Exception as ex:
            print(ex)
            return jsonify({"success": False, "message": "Failed to send email."}), 500

        return jsonify({"success": True, "message": "Client added successfully, and email sent."}), 201


    # Handle GET request to render the client management page
    coach_id = current_user.id  # Adjust based on your logic
    clients = Client.query.filter_by(coach_id=coach_id).all()

    # Convert SQLAlchemy objects to dictionaries for JSON compatibility
    clients_data = [
        {
            "id": client.id,
            "first_name": client.first_name,
            "last_name": client.last_name,
            "email": client.email,
            "start_date": client.start_date.isoformat() if client.start_date else None,
            "end_date": client.end_date.isoformat() if client.end_date else None,
            "frequency": client.frequency
        } for client in clients
    ]

    return render_template('add_client.html', clients=clients_data)

@app.route('/update_client/<int:client_id>', methods=['POST'])
def update_client(client_id):
    data = request.get_json()
    client = Client.query.get(client_id)
    if client:
        client.first_name = data.get('first_name')
        client.last_name = data.get('last_name')
        client.email = data.get('email')

        # Convert start_date and end_date to date objects
        if data.get('start_date'):
            client.start_date = datetime.strptime(data.get('start_date'), '%Y-%m-%d').date()
        if data.get('end_date'):
            client.end_date = datetime.strptime(data.get('end_date'), '%Y-%m-%d').date()

        client.frequency = data.get('frequency')
        db.session.commit()
        return jsonify({"message": "Client updated successfully"}), 200
    return jsonify({"message": "Client not found"}), 404

@app.route('/delete_client/<int:client_id>', methods=['DELETE'])
def delete_client(client_id):
    client = Client.query.get(client_id)
    if client:
        db.session.delete(client)
        db.session.commit()
        return jsonify({"message": "Client deleted successfully"}), 200
    return jsonify({"message": "Client not found"}), 404

def generate_random_password(length=10):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms_of_service')
def terms_of_service():
    return render_template('terms_of_service.html')

# Serializer for generating secure tokens
serializer = URLSafeTimedSerializer(app.secret_key)

# Store reset tokens temporarily (use a database in production)
reset_tokens = {}

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    return render_template('forgot_password.html')

# Azure Communication Services connection string
connection_string = "endpoint=https://freddie-email.india.communication.azure.com/;accesskey=Czr5YUAXaL6ngxsZRg8K0TJ04MA6OOc7xIJNJ4HIXYtgKVqnogqbJQQJ99AHACULyCppJDEQAAAAAZCSvvrg"
client = EmailClient.from_connection_string(connection_string)

@app.route('/send_link', methods=['POST'])
def send_link():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the email belongs to a User
        user = User.query.filter_by(email=email).first()
        print(f"Email checked: {email}")

        if not user:
            flash("Email not found.", "error")
            print(f"[INFO] Email '{email}' not found in the database.")
            return redirect(url_for('forgot_password'))

        # Generate a secure reset token
        token = serializer.dumps(email, salt='password-reset-salt')

        # Password reset link
        reset_link = url_for('reset_password', token=token, _external=True)

        # Prepare the email content
        subject = "Freddie AI Coach - Password Reset Request"
        plain_text_body = (
            f"Hello,\n\n"
            f"We received a request to reset your password for Freddie AI Coach. If this was not you, please ignore this email.\n\n"
            f"To reset your password, please click the link below:\n{reset_link}\n\n"
            f"Thank you,\n"
            f"The Freddie AI Coach Team"
        )
        html_body = f"""
        <html>
            <body>
                <h1>Freddie AI Coach</h1>
                <h2>Password Reset Request</h2>
                <p>Hello,</p>
                <p>We received a request to reset your password for Freddie AI Coach. If this was not you, please ignore this email.</p>
                <p>To reset your password, please click the link below:</p>
                <p><a href="{reset_link}" style="color: blue; text-decoration: underline;">Reset Password</a></p>
                <p>Thank you,</p>
                <p>The Freddie AI Coach Team</p>
            </body>
        </html>
        """

        # Build the message
        message = {
            "senderAddress": "DoNotReply@eduvitz.co.in",  # Your sender email
            "recipients": {
                "to": [{"address": email}]
            },
            "content": {
                "subject": subject,
                "plainText": plain_text_body,
                "html": html_body,
            },
        }

        try:
            # Send the email using Azure Communication Services
            poller = client.begin_send(message)
            result = poller.result()
            print("Message sent successfully.")

            # Flash a success message and redirect
            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for('forgot_password'))
        
        except Exception as ex:
            print(f"[ERROR] Failed to send email: {ex}")
            flash("An error occurred while sending the reset link. Please try again.", "error")
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

import re

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Invalid or missing token."}), 400

    try:
        # Validate token and extract email
        email = serializer.loads(token, salt='password-reset-salt', max_age=900)  # Token expires in 15 minutes
    except Exception:
        return jsonify({"error": "The password reset link is invalid or has expired."}), 400

    if request.method == 'POST':
        new_password = request.json.get('password')  # Use JSON data for AJAX
        confirm_password = request.json.get('confirm_password')

        # Password complexity requirements
        password_requirements = [
            (r".{8,}", "Password must be at least 8 characters long."),
            (r"[A-Z]", "Password must contain at least one uppercase letter."),
            (r"[a-z]", "Password must contain at least one lowercase letter."),
            (r"\d", "Password must contain at least one number."),
            (r"[!@#$%^&*(),.?\":{}|<>]", "Password must contain at least one special character."),
        ]

        # Validate password complexity
        for pattern, error_message in password_requirements:
            if not re.search(pattern, new_password):
                return jsonify({"error": error_message}), 400

        # Check if passwords match
        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match."}), 400

        # Retrieve the user and update the password
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = new_password  # Hash this in production
            db.session.commit()
            return jsonify({"success": "Your password has been reset successfully.", 
            "login_url": url_for('login')}),200  # Include login URL in response
        else:
            return jsonify({"error": "User not found."}), 404

    return render_template('reset_password.html', token=token)

@app.route('/agree', methods=['POST'])
def save_user_agreement():
    # Check if the user is logged in
    if not current_user.is_authenticated:
        return {"error": "User not logged in"}, 401

    # Get the logged-in user's customer number (cust_no)
    cust_no = current_user.cust_no

    # Extract the terms version from the request body
    request_data = request.get_json()
    terms_version = request_data.get("terms_version", "v1.0")  # Default to "v1.0" if not provided

    try:
        # Create and save the user agreement
        agreement = UserAgreement(cust_no=cust_no, terms_version=terms_version)
        db.session.add(agreement)

        # Update the `has_agreed` flag for the user
        user = User.query.filter_by(cust_no=cust_no).first()
        if user:
            user.has_agreed = True
            db.session.add(user)

        # Commit the changes
        db.session.commit()

        return {"success": True, "message": "User agreement saved successfully."}, 200
    except Exception as e:
        db.session.rollback()
        return {"error": f"Failed to save agreement: {str(e)}"}, 500




# Placeholder function to retrieve email from cust_no
def get_email_from_cust_no(cust_no):
    # Replace this with logic to fetch the email from the database using cust_no
    # For example:
    # customer = Customer.query.filter_by(cust_no=cust_no).first()
    # return customer.email if customer else None
    # For this example, we're just returning a dummy email
    return "sumaiyakauser2019@gmail.com"  # Dummy email for now



