import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt

app = Flask(__name__)
app.secret_key = 'f38b0e0a7f7b4f97a2b9a2f6c128b8d3'  # Your secret key

# Updated PostgreSQL database configuration using psycopg2 driver
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://default:7PncvCB6DHOd@ep-orange-night-a4sgorcj.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable the modification tracking

# Initialize SQLAlchemy and Flask-Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define the User model with the specified table name
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

# Define the Asset model
class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Asset {self.name}>'

# Password validation function
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must contain at least one special character."
    return None

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            session['username'] = username  # Store username in session
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.")

    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        password_error = validate_password(password)
        if password_error:
            flash(password_error)
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash("User already exists!")
            return render_template('register.html')
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            new_user = User(username=username, password_hash=hashed_password.decode('utf-8'))
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! You can now <a href='/login'>login</a>.")
            return redirect(url_for('login'))

    return render_template('register.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    username = session.get('username', 'Guest')  # Get username from session
    assets = Asset.query.all()
    return render_template('dashboard.html', assets=assets, username=username)

# Create Asset route
@app.route('/create_asset', methods=['GET', 'POST'])
def create_asset():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        status = request.form['status']
        owner = request.form['owner']

        new_asset = Asset(name=name, description=description, status=status, owner=owner)
        db.session.add(new_asset)
        db.session.commit()
        flash("Asset created successfully!")
        return redirect(url_for('dashboard'))

    users = User.query.all()  # Get all users for the dropdown
    return render_template('create_asset.html', users=users)

# Asset Detail route
@app.route('/asset/<int:asset_id>', methods=['GET', 'POST'])
def asset_detail(asset_id):
    asset = Asset.query.get(asset_id)

    if not asset:
        return "Asset not found.", 404

    if request.method == 'POST':
        if 'status' in request.form and 'owner' in request.form and 'description' in request.form:
            status = request.form['status']
            owner = request.form['owner']
            description = request.form['description']
            asset.status = status
            asset.owner = owner
            asset.description = description
            db.session.commit()
            flash(f"Asset '{asset.name}' updated successfully!")
        elif 'delete' in request.form:
            db.session.delete(asset)
            db.session.commit()
            flash(f"Asset '{asset.name}' deleted successfully!")
            return redirect(url_for('dashboard'))

        return redirect(url_for('asset_detail', asset_id=asset_id))

    return render_template('asset_detail.html', asset=asset, asset_id=asset_id)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear username from session
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
