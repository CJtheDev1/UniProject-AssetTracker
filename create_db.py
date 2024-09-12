from app import app, db

# Create tables in the databases
with app.app_context():
    db.create_all()
