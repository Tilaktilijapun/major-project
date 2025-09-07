import os
from pathlib import Path
from flask import Blueprint, render_template, request, jsonify, flash
from flask_login import login_required, current_user
from models import User
from extensions import db
from werkzeug.security import generate_password_hash

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/')
@login_required
def settings():
    return render_template('settings.html')

@settings_bp.route('/api/settings/profile', methods=['GET', 'POST'])
@login_required
def profile_settings():
    if request.method == 'GET':
        try:
            user_data = {
                'username': current_user.username,
                'email': current_user.email,
                'timezone': getattr(current_user, 'timezone', 'UTC')
            }
            return jsonify(user_data)
        except Exception as e:
            return jsonify({'error': f'Failed to fetch settings: {str(e)}'}), 500

    elif request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            timezone = data.get('timezone')

            # Validate inputs
            if not username or len(username) < 3:
                return jsonify({'success': False, 'message': 'Username must be at least 3 characters long'}), 400
            if not email or '@' not in email:
                return jsonify({'success': False, 'message': 'Invalid email address'}), 400
            if password and len(password) < 5:
                return jsonify({'success': False, 'message': 'Password must be at least 5 characters long'}), 400

            # Check for unique username and email
            if username != current_user.username and User.query.filter_by(username=username).first():
                return jsonify({'success': False, 'message': 'Username already taken'}), 400
            if email != current_user.email and User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already in use'}), 400

            # Update user
            current_user.username = username
            current_user.email = email
            if password:
                current_user.password = generate_password_hash(password)
            current_user.timezone = timezone or 'UTC'
            db.session.commit()

            return jsonify({'success': True, 'message': 'Settings updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': f'Failed to update settings: {str(e)}'}), 500