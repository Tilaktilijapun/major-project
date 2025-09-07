from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from models import User
from extensions import db

auth_bp = Blueprint('auth', __name__)

# LOGIN ROUTE
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect based on role
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard.dashboard'))  # change to your admin dashboard endpoint
        else:
            return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('auth/login.html')

    # Handle JSON/AJAX or form submission
    if request.is_json:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
    else:
        email = request.form.get('email')
        password = request.form.get('password')

    if not email or not password:
        message = 'Please fill in all fields'
        if request.is_json:
            return jsonify({'message': message}), 400
        flash(message, 'error')
        return render_template('auth/login.html')

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        # login successful
        login_user(user)

        # Redirect based on user role
        if user.role == 'admin':
            redirect_url = url_for('admin_dashboard.dashboard')  # admin dashboard route
        else:
            redirect_url = url_for('index')

        if request.is_json:
            return jsonify({'redirect': redirect_url}), 200
        return redirect(redirect_url)

    message = 'Invalid email or password'
    if request.is_json:
        return jsonify({'message': message}), 401
    flash(message, 'error')
    return render_template('auth/login.html')


# SIGNUP ROUTE
@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    # If already logged in, redirect based on role
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard.dashboard'))
        else:
            return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('auth/signup.html')

    if request.is_json:
        data = request.get_json()
        username = data.get('name')  # Adjust key if needed
        email = data.get('email')
        password = data.get('password')
    else:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

    if not username or not email or not password:
        message = 'Please fill in all fields'
        if request.is_json:
            return jsonify({'message': message}), 400
        flash(message, 'error')
        return render_template('auth/signup.html')

    if User.query.filter_by(email=email).first():
        message = 'Email already registered'
        if request.is_json:
            return jsonify({'message': message}), 409
        flash(message, 'error')
        return render_template('auth/signup.html')

    try:
        user = User(username=username, email=email, role='user')  # default role user
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)

        # Redirect based on role (though new user is always 'user')
        redirect_url = url_for('index')

        if request.is_json:
            return jsonify({'redirect': redirect_url}), 201
        return redirect(redirect_url)

    except Exception as e:
        db.session.rollback()
        message = f'Registration failed: {str(e)}'
        if request.is_json:
            return jsonify({'message': message}), 500
        flash(message, 'error')
        return render_template('auth/signup.html')


# LOGOUT ROUTE
@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


# FUTURE UPDATES PAGE (example with login_required)
@auth_bp.route('/future_updates')
@login_required
def future_updates():
    return render_template('future_updates.html')
