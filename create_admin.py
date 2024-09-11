from app import app, db, User
from flask_bcrypt import Bcrypt

# Initialize Bcrypt
bcrypt = Bcrypt()

def create_admin():
    with app.app_context():
        # Check if the admin user already exists
        if User.query.filter_by(username='admin').first():
            print("Admin user already exists.")
            return

        # Create an admin user
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin_password')  # Replace with a secure password

        db.session.add(admin)
        db.session.commit()

        print("Admin user created successfully!")

if __name__ == '__main__':
    create_admin()
