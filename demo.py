import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, flash, redirect, url_for, request
from flask_login import login_required, current_user
from models import User
from extensions import db

demo_bp = Blueprint('demo', __name__)

@demo_bp.route('/demo')
@login_required
def demo_page():
    return render_template('demo.html')

# Helper function to check demo status
def check_demo_status(user):
    if user.is_subscribed:
        return 'subscribed'
    if not user.is_demo_active or not user.demo_start_date: 
        return 'inactive'
    demo_end = user.demo_start_date + timedelta(days=14)
    days_remaining = (demo_end - datetime.utcnow()).days
    if datetime.utcnow() > demo_end:
        user.is_demo_active = False
        db.session.commit()
        return 'expired'
    return {'demo_status': 'active', 'days_remaining': days_remaining}


# Activate demo for a user
def activate_demo(user):
    if not user.is_demo_active and not user.is_subscribed and not user.demo_start_date:
        user.demo_start_date = datetime.utcnow()
        user.is_demo_active = True
        db.session.commit()
        flash('Your 14-day demo has started!', 'success')

# Middleware to restrict access post-demo
@demo_bp.before_app_request
def restrict_access():
    if current_user.is_authenticated and request.endpoint not in ['demo.subscribe', 'demo.demo_status', 'static', 'auth.logout', 'index']:
        demo_status = check_demo_status(current_user)
        if demo_status == 'expired' and not current_user.is_subscribed:
            flash('Your demo has expired. Please subscribe to continue.', 'warning')
            return redirect(url_for('demo.subscribe'))

@demo_bp.route('/demo')
@login_required
def demo_status():
    demo_status = check_demo_status(current_user)
    if demo_status == 'subscribed':
        flash('You have an active subscription.', 'success')
    elif demo_status == 'inactive':
        activate_demo(current_user)
        demo_status = check_demo_status(current_user)
    elif demo_status == 'expired':
        flash('Your demo has expired. Please subscribe to continue.', 'warning')
    elif isinstance(demo_status, dict) and demo_status['status'] == 'active':
        days = demo_status['days_remaining']
        if days == 1:
            flash('Your demo expires tomorrow! Subscribe now to continue access.', 'warning')
        elif days <= 3:
            flash(f'Your demo has {days} days remaining.', 'info')
        else:
            flash(f'Your demo is active with {days} days remaining.', 'success')
    return render_template('demo.html', demo_status=demo_status)

@demo_bp.route('/api/demo/status')
@login_required
def api_demo_status():
    demo_status = check_demo_status(current_user)
    if isinstance(demo_status, dict):
        return jsonify(demo_status)
    return jsonify({'demo_status': demo_status})

@demo_bp.route('/subscribe')
@login_required
def subscribe():
    if current_user.is_subscribed:
        flash('You already have an active subscription.', 'success')
        return redirect(url_for('index'))
    return render_template('subscribe.html')

@demo_bp.route('/api/subscribe', methods=['POST'])
@login_required
def api_subscribe():
    # Placeholder for subscription logic (e.g., integrate with Stripe or PayPal)
    try:
        # Simulate successful payment
        current_user.is_subscribed = True
        current_user.is_demo_active = False
        db.session.commit()
        return jsonify({'success': True, 'message': 'Subscription activated successfully!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Subscription failed: {str(e)}'}), 500