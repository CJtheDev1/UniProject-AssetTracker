import re
from flask import Flask, render_template, request, redirect, url_for, flash
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for flashing messages

# In-memory dictionary to store users and assets
users = {}
assets = {
    1: {"name": "Laptop - MacBook Pro", "description": "A high-performance laptop", "status": "In Use",
        "owner": "John Doe"},
    2: {"name": "Printer - HP LaserJet", "description": "Office printer", "status": "Available", "owner": "Jane Smith"},
    3: {"name": "Phone - iPhone 12", "description": "Assigned company phone", "status": "Assigned",
        "owner": "Michael Brown"},
    4: {"name": "Monitor - Dell 24 inch", "description": "Monitor for IT department", "status": "In Storage",
        "owner": "Emily Davis"}
}


# Password validation function
def validate_password(password):
    """ Validate password with at least 8 characters and 1 special character """
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

        if username in users:
            if bcrypt.checkpw(password.encode('utf-8'), users[username]):
                return redirect(url_for('dashboard', user_email=username))
            else:
                flash("Invalid password.")
        else:
            flash("User not found.")

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

        if username in users:
            flash("User already exists!")
            return render_template('register.html')
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users[username] = hashed_password
            flash("Registration successful! You can now <a href='/login'>login</a>.")
            return redirect(url_for('login'))

    return render_template('register.html')


# Dashboard route
@app.route('/dashboard')
def dashboard():
    user_email = request.args.get('user_email', 'Guest')
    return render_template('dashboard.html', assets=assets, user_email=user_email)


# Create Asset route
@app.route('/create_asset', methods=['GET', 'POST'])
def create_asset():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        status = request.form['status']
        owner = request.form['owner']

        new_id = max(assets.keys()) + 1 if assets else 1
        assets[new_id] = {
            "name": name,
            "description": description,
            "status": status,
            "owner": owner
        }
        return redirect(url_for('dashboard'))

    return render_template('create_asset.html')


# Asset Detail route
@app.route('/asset/<int:asset_id>', methods=['GET', 'POST'])
def asset_detail(asset_id):
    asset = assets.get(asset_id)

    if not asset:
        return "Asset not found.", 404

    if request.method == 'POST':
        if 'status' in request.form and 'owner' in request.form and 'description' in request.form:
            # Update asset details
            status = request.form['status']
            owner = request.form['owner']
            description = request.form['description']
            assets[asset_id] = {
                "name": asset["name"],
                "status": status,
                "owner": owner,
                "description": description
            }
            flash(f"Asset '{asset['name']}' updated successfully!")
        elif 'delete' in request.form:
            # Delete asset
            del assets[asset_id]
            flash(f"Asset '{asset['name']}' deleted successfully!")
            return redirect(url_for('dashboard'))

        return redirect(url_for('asset_detail', asset_id=asset_id))

    return render_template('asset_detail.html', asset=asset, asset_id=asset_id)


# Logout route
@app.route('/logout')
def logout():
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
