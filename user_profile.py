from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import User
from extensions import db

# Use underscore to avoid dash-related issues in url_for
user_profile_bp = Blueprint('user_profile', __name__)

@user_profile_bp.route('/profile', methods=['GET'])
@login_required
def profile():
    user = current_user
    return render_template('user-profile.html', user=user)

@user_profile_bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    user = current_user

    user.username = request.form.get('username')
    user.email = request.form.get('email')
    user.full_name = request.form.get('full_name')
    user.phone = request.form.get('phone')
    user.location = request.form.get('location')

    db.session.commit()
    flash("Profile updated successfully!", "success")
    return redirect(url_for('user_profile.profile'))
