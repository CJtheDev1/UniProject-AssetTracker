import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt

app = Flask(__name__)
app.secret_key = 'f38b0e0a7f7b4f97a2b9a2f6c128b8d3'  # Your secret key

# PostgreSQL database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://default:7PncvCB6DHOd@ep-orange-night-a4sgorcj.us-east-1.aws.neon.tech:5432/verceldb?sslmode=require'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and Flask-Migrate
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    permissions = db.Column(db.String(255), default='user')

# Asset model
class Asset(db.Model):
    __tablename__ = 'assets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Asset {self.name}>'

# Password validation
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
            session['username'] = username
            session['permissions'] = user.permissions
            session['user_id'] = user.id  # Store user ID in session
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
    username = session.get('username', 'Guest')
    permissions = session.get('permissions', 'user')  # Get permissions from session
    assets = Asset.query.all()
    return render_template('dashboard.html', assets=assets, username=username, permissions=permissions)

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

    users = User.query.all()
    return render_template('create_asset.html', users=users)

# User Management route
@app.route('/user_management', methods=['GET', 'POST'])
def user_management():
    users = User.query.all()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        user = User.query.get(user_id)

        if action == 'delete':
            db.session.delete(user)
            db.session.commit()
            flash(f"User '{user.username}' deleted successfully!")
            return jsonify({'success': True, 'message': f"User '{user.username}' deleted successfully!"})
        elif action == 'update' and request.form.get('permissions'):
            new_permissions = request.form.get('permissions')
            user.permissions = new_permissions
            db.session.commit()
            flash(f"User '{user.username}' permissions updated to '{new_permissions}'.")
            return jsonify({'success': True, 'message': f"User '{user.username}' permissions updated to '{new_permissions}'."})

        return jsonify({'success': False, 'message': 'Invalid action or missing permissions.'}), 400

    return render_template('user_management.html', users=users)

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
    session.pop('username', None)
    session.pop('permissions', None)
    session.pop('user_id', None)  # Clear user ID from session
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
