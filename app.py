
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import stripe

# Initialize Flask application
app = Flask(__name__)

# Configure SQLAlchemy
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Stripe configuration
stripe_secret_key = 'sk_test_51P2AEeP3jLWWEkkLcx5sgF24BNmyNVFasBaOVsPL5dpEvRHIrBf7vS5ZHD5bymOd9gsKcfpJOHrp0UMB5zkOrtV4009hajkGNf'
stripe_publish_key = 'pk_test_51P2AEeP3jLWWEkkLMDg24j89ONmq3R7jBmTqzDwHoZX6kWnTfIVVADnDvxQvkMrKrjFFdxiNvCtODjas9oD5JlY000JBa23LMi'
stripe.api_key = stripe_secret_key

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    cart = db.relationship('CartItem', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# Login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Product model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Integer, nullable=False)  # Store price in cents
    image = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<Product {self.name}>'


@app.route('/product/<int:product_id>', methods=['GET'], endpoint='product_detail')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


# CartItem model
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    product = db.relationship('Product')

# Custom Product Admin View
class ProductAdmin(ModelView):
    def on_model_change(self, form, model, is_created):
        if form.price.data:
            # Convert price to cents before saving
            model.price = int(float(form.price.data) * 100)
        super(ProductAdmin, self).on_model_change(form, model, is_created)

# Flask-Admin setup
admin = Admin(app, name='Admin Panel')
admin.add_view(ProductAdmin(Product, db.session))
admin.add_view(ModelView(User, db.session))

# Login manager user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/collection')
def collection():
    products = Product.query.all()
    return render_template('collection.html', products=products)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin.index'))
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()

    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=1)
        db.session.add(cart_item)
    db.session.commit()
    flash('Product added to cart!', 'success')
    return redirect(url_for('cart'))

@app.route('/increase_quantity/<int:cart_item_id>', methods=['POST'])
@login_required
def increase_quantity(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    cart_item.quantity += 1
    db.session.commit()
    return redirect(url_for('cart'))

@app.route('/decrease_quantity/<int:cart_item_id>', methods=['POST'])
@login_required
def decrease_quantity(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    if cart_item.quantity > 1:
        cart_item.quantity -= 1
    else:
        db.session.delete(cart_item)
    db.session.commit()
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = CartItem.query.get_or_404(cart_item_id)
    db.session.delete(cart_item)
    db.session.commit()
    flash('Product removed from cart.', 'success')
    return redirect(url_for('cart'))



@app.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.product.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('Your cart is empty.', 'warning')
        return redirect(url_for('index'))

    line_items = [{
        'price_data': {
            'currency': 'usd',
            'product_data': {
                'name': item.product.name,
                'images': [item.product.image],
            },
            'unit_amount': item.product.price,
        },
        'quantity': item.quantity,
    } for item in cart_items]

    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=line_items,
        mode='payment',
        success_url=url_for('success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=url_for('cancel', _external=True),
    )

    return redirect(session.url, code=303)

@app.route('/success')
def success():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    for item in cart_items:
        db.session.delete(item)
    db.session.commit()
    return render_template('success.html')

@app.route('/cancel')
def cancel():
    return render_template('cancel.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Custom CLI commands
@app.cli.command('populate-db')
def populate_db():
    """Populate the database with sample data."""
    db.create_all()

    if Product.query.count() == 0:
        sample_products = [
            Product(name='Product 1', price=1000, image='https://example.com/product1.jpg'),
            Product(name='Product 2', price=1500, image='https://example.com/product2.jpg'),
        ]
        db.session.bulk_save_objects(sample_products)
        db.session.commit()
        print("Database populated with sample data.")
    else:
        print("Database already populated.")

@app.cli.command('create-admin')
def create_admin():
    """Create an admin user."""
    db.create_all()
    username = input('Enter username: ')
    password = input('Enter password: ')
    admin = User(username=username, is_admin=True)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print('Admin user created.')

@app.cli.command('init-db')
def init_db():
    """Initialize the database."""
    db.create_all()
    print('Database initialized.')


if __name__ == '__main__':
    app.run(debug=True)

    