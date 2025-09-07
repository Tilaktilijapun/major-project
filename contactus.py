from flask import Blueprint, render_template, request, flash, redirect, url_for
from datetime import datetime
from models import ContactMessage
from extensions import db
from notifications import send_notifications
from flask_login import current_user
from flask import jsonify
from flask_login import login_required

contactus_bp = Blueprint('contactus', __name__)

@contactus_bp.route('/contact-us')
@login_required
def contact():
    return render_template('contactus.html')

@contactus_bp.route('/contact-us/submit', methods=['POST'])
def submit_contact_form():
    try:
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')
        
        # Validate required fields
        if not all([name, email, subject, message]):
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('contactus.show_contact_form'))
        
        # Create new contact message
        new_message = ContactMessage(
            name=name,
            email=email,
            subject=subject,
            message=message,
            submission_date=datetime.utcnow(),
            status='pending'
        )
        
        # Save to database
        db.session.add(new_message)
        db.session.commit()
        
        # Send notification to admin
        send_notification(
            'New Contact Form Submission',
            f'New message from {name} ({email})\nSubject: {subject}',
            'admin'
        )
        
        flash('Thank you for your message. We will get back to you soon!', 'success')
        return redirect(url_for('contactus.show_contact_form'))
        
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while submitting your message. Please try again.', 'error')
        return redirect(url_for('contactus.show_contact_form'))

@contactus_bp.route('/api/contact-messages')

def get_contact_messages():
    # Only accessible by admin
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    messages = ContactMessage.query.order_by(
        ContactMessage.submission_date.desc()
    ).all()
    
    return jsonify([
        {
            'id': msg.id,
            'name': msg.name,
            'email': msg.email,
            'subject': msg.subject,
            'message': msg.message,
            'submission_date': msg.submission_date.strftime('%Y-%m-%d %H:%M:%S'),
            'status': msg.status
        } for msg in messages
    ])

@contactus_bp.route('/api/contact-messages/<int:message_id>/status', methods=['PUT'])

def update_message_status(message_id):
    # Only accessible by admin
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    message = ContactMessage.query.get_or_404(message_id)
    new_status = request.json.get('status')
    
    if new_status not in ['pending', 'in_progress', 'resolved']:
        return jsonify({'error': 'Invalid status'}), 400
    
    message.status = new_status
    db.session.commit()
    
    return jsonify({'message': 'Status updated successfully'})  