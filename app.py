from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuration for two databases: one for users, one for assets
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///assets.db'  # Asset database
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:///users.db'  # User credentials database
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'yoursecretkey'

# Initialize the SQLAlchemy extension
db = SQLAlchemy(app)


# Define User model (bound to users.db)
class User(db.Model):
    __bind_key__ = 'users'  # Connect this model to the 'users' database
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


# Define Asset model (bound to assets.db)
class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(100), nullable=False)


# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password
        hashed_password = generate_password_hash(password, method='sha256')

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another.', 'error')
            return redirect(url_for('register'))

        # Create new user
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find user by username
        user = User.query.filter_by(username=username).first()

        # Check password
        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')


# Route for dashboard displaying all assets
@app.route('/dashboard')
def dashboard():
    assets = Asset.query.all()
    return render_template('dashboard.html', assets=assets)


# Route to create a new asset
@app.route('/create_asset', methods=['GET', 'POST'])
def create_asset():
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        owner = request.form['owner']

        # Create new asset
        new_asset = Asset(name=name, status=status, owner=owner)
        db.session.add(new_asset)
        db.session.commit()

        return redirect(url_for('dashboard'))

    return render_template('create_asset.html')


# Initialize the databases and create tables if they don't exist
with app.app_context():
    db.create_all()

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
