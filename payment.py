from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from flask_login import login_required, current_user
from models import Subscription, Payment
from extensions import db  # Assume db is configured with Flask-SQLAlchemy

payment_bp = Blueprint('payment', __name__)

@payment_bp.route('/pricing', methods=['GET'])
@login_required
def payment():
    return render_template('payment.html')

@payment_bp.route('/api/payment', methods=['POST'])
@login_required
def process_payment():
    # Get form data
    data = request.form
    card_number = data.get('card_number', '').replace(' ', '')
    expiry_date = data.get('expiry_date', '')
    cvc = data.get('cvc', '')
    cardholder_name = data.get('cardholder_name', '')
    address_line1 = data.get('address_line1', '')
    city = data.get('city', '')
    postal_code = data.get('postal_code', '')

    # Basic validation
    if not all([card_number, expiry_date, cvc, cardholder_name, address_line1, city, postal_code]):
        return jsonify({'message': 'All fields are required'}), 400
    
    if len(card_number) != 16 or not card_number.isdigit():
        return jsonify({'message': 'Invalid card number'}), 400
    
    if not (len(cvc) == 3 or len(cvc) == 4) or not cvc.isdigit():
        return jsonify({'message': 'Invalid CVC'}), 400
    
    # Mock payment processing (replace with real payment gateway)
    try:
        # Simulate payment success
        amount = 20.00  # Matches Rs20.00 from payment.html
        # In a real scenario, integrate with a payment gateway API here
        # Example: stripe.Charge.create(amount=amount*100, currency='usd', source=card_number, description='AIVivid Subscription')
        
        # Log payment (assuming a Payment model exists)
        from models import Payment  # Assume Payment model with user_id, amount, status
        new_payment = Payment(user_id=current_user.id, amount=amount, status='completed')
        db.session.add(new_payment)
        db.session.commit()

        session['subscription_active'] = True
        return jsonify({'message': 'Payment successful! Subscription activated.'}), 200
    except Exception as e:
        return jsonify({'message': f'Payment failed: {str(e)}'}), 500

@payment_bp.route('/user_dashboard/user_dashboard')
@login_required
def user_dashboard():
    subscription_active = session.get('subscription_active', False)
    return render_template('dashboard.html', subscription_active=subscription_active)  # Assume dashboard.html exists