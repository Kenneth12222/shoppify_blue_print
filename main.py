

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask.views import MethodView
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

# Class-based Views
class IndexView(MethodView):
    def get(self):
        products = Product.query.all()
        return render_template('index.html', products=products)

class LoginView(MethodView):
    def get(self):
        form = LoginForm()
        return render_template('login.html', form=form)

    def post(self):
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

class RegisterView(MethodView):
    def get(self):
        return render_template('register.html')

    def post(self):
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

class ProfileView(MethodView):
    @login_required
    def get(self):
        return render_template('profile.html')

class CartView(MethodView):
    @login_required
    def get(self):
        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        total_price = sum(item.product.price * item.quantity for item in cart_items)
        return render_template('cart.html', cart_items=cart_items, total_price=total_price)

class AddToCartView(MethodView):
    @login_required
    def post(self, product_id):
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

class ModifyCartItemView(MethodView):
    @login_required
    def post(self, cart_item_id, action):
        cart_item = CartItem.query.get_or_404(cart_item_id)
        if action == 'increase':
            cart_item.quantity += 1
        elif action == 'decrease':
            if cart_item.quantity > 1:
                cart_item.quantity -= 1
            else:
                db.session.delete(cart_item)
        elif action == 'remove':
            db.session.delete(cart_item)
        db.session.commit()
        return redirect(url_for('cart'))

@app.route('/increase_quantity/<int:cart_item_id>', methods=['POST'])
@login_required
def increase_quantity(cart_item_id):
    cart_item = CartItem.query.get(cart_item_id)
    if cart_item:
        cart_item.quantity += 1
        db.session.commit()
    return redirect(url_for('cart'))

@app.route('/decrease_quantity/<int:cart_item_id>', methods=['POST'])
@login_required
def decrease_quantity(cart_item_id):
    cart_item = CartItem.query.get(cart_item_id)
    if cart_item and cart_item.quantity > 1:
        cart_item.quantity -= 1
        db.session.commit()
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
@login_required
def remove_from_cart(cart_item_id):
    cart_item = CartItem.query.get(cart_item_id)
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
    return redirect(url_for('cart'))

class CheckoutView(MethodView):
    @login_required
    def post(self):
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
 
class SuccessView(MethodView):
    def get(self):
        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        for item in cart_items:
            db.session.delete(item)
        db.session.commit()
        return render_template('success.html')

class CancelView(MethodView):
    def get(self):
        return render_template('cancel.html')

class LogoutView(MethodView):
    @login_required
    def get(self):
        logout_user()
        return redirect(url_for('index'))


@app.route('/product/<int:product_id>', methods=['GET'], endpoint='product_detail')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)


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

# Register class-based views as routes
app.add_url_rule('/', view_func=IndexView.as_view('index'))
app.add_url_rule('/login', view_func=LoginView.as_view('login'))
app.add_url_rule('/register', view_func=RegisterView.as_view('register'))
app.add_url_rule('/profile', view_func=ProfileView.as_view('profile'))
app.add_url_rule('/cart', view_func=CartView.as_view('cart'))
app.add_url_rule('/add_to_cart/<int:product_id>', view_func=AddToCartView.as_view('add_to_cart'))
app.add_url_rule('/modify_cart_item/<int:cart_item_id>/<string:action>', view_func=ModifyCartItemView.as_view('modify_cart_item'))
app.add_url_rule('/checkout', view_func=CheckoutView.as_view('checkout'))
app.add_url_rule('/success', view_func=SuccessView.as_view('success'))
app.add_url_rule('/cancel', view_func=CancelView.as_view('cancel'))
app.add_url_rule('/logout', view_func=LogoutView.as_view('logout'))

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
