from flask import Blueprint, render_template
from models import Contact, PricingPlan, User, Threat, Device
from extensions import db
from datetime import datetime

static_pages = Blueprint('static_pages', __name__)

@static_pages.route('/about')
def about():
    return render_template('aboutus.html')

@static_pages.route('/contact')
def contact():
    return render_template('contactus.html')

@static_pages.route('/pricing')
def pricing():
    return render_template('pricing.html')

@static_pages.route('/api/contact/submit', methods=['POST'])
def submit_contact():
    try:
        data = request.get_json()
        contact = Contact(
            name=data['name'],
            email=data['email'],
            subject=data['subject'],
            message=data['message'],
            created_at=datetime.now()
        )
        db.session.add(contact)
        db.session.commit()
        
        # Send notification email to admin
        send_admin_notification(contact)
        
        return jsonify({'message': 'Contact form submitted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@static_pages.route('/api/pricing/plans')
def get_pricing_plans():
    try:
        plans = PricingPlan.query.all()
        return jsonify({
            'plans': [plan.to_dict() for plan in plans],
            'features': get_plan_features(),
            'current_discounts': get_active_discounts()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@static_pages.route('/api/company/stats')
def get_company_stats():
    try:
        return jsonify({
            'total_users': User.query.count(),
            'threats_detected': Threat.query.count(),
            'devices_protected': Device.query.count(),
            'customer_satisfaction': calculate_satisfaction_rate(),
            'uptime_percentage': calculate_system_uptime(),
            'total_revenue': calculate_total_revenue(),
            'monthly_revenue': calculate_monthly_revenue(),
            'monthly_active_users': calculate_monthly_active_users(),
            'monthly_threats_detected': calculate_monthly_threats_detected(),
            'monthly_devices_protected': calculate_monthly_devices_protected(),
            'monthly_support_tickets': calculate_monthly_support_tickets(),
            'monthly_new_users': calculate_monthly_new_users(),
            'monthly_churn_rate': calculate_monthly_churn_rate(),
            'monthly_satisfaction_rate': calculate_monthly_satisfaction_rate(),
            'monthly_revenue_growth_rate': calculate_monthly_revenue_growth_rate(),
            'monthly_active_user_growth_rate': calculate_monthly_active_user_growth_rate(),
            'monthly_threat_detection_growth_rate': calculate_monthly_threat_detection_growth_rate(),
            'monthly_device_protection_growth_rate': calculate_monthly_device_protection_growth_rate(),
            'monthly_support_ticket_growth_rate': calculate_monthly_support_ticket_growth_rate(),
            'monthly_new_users_growth_rate': calculate_monthly_new_users_growth_rate(),
            'monthly_churn_rate_growth_rate': calculate_monthly_churn_rate_growth_rate(),
            'monthly_satisfaction_rate_growth_rate': calculate_monthly_satisfaction_rate_growth_rate(),
            'monthly_revenue_growth_rate': calculate_monthly_revenue_growth_rate(),
            'monthly_active_user_growth_rate': calculate_monthly_active_user_growth_rate(),
            'monthly_threat_detection_growth_rate': calculate_monthly_threat_detection_growth_rate(),
            'monthly_device_protection_growth_rate': calculate_monthly_device_protection_growth_rate(),
            'monthly_support_ticket_growth_rate': calculate_monthly_support_ticket_growth_rate(),
            'monthly_new_users_growth_rate': calculate_monthly_new_users_growth_rate(),
            'monthly_churn_rate_growth_rate': calculate_monthly_churn_rate_growth_rate(),
            'monthly_satisfaction_rate_growth_rate': calculate_monthly_satisfaction_rate_growth_rate(),
            'monthly_revenue_growth_rate': calculate_monthly_revenue_growth_rate(),
            'monthly_active_user_growth_rate': calculate_monthly_active_user_growth_rate(),
            'monthly_threat_detection_growth_rate': calculate_monthly_threat_detection_growth_rate(),
            'monthly_device_protection_growth_rate': calculate_monthly_device_protection_growth_rate(),
            'monthly_support_ticket_growth_rate': calculate_monthly_support_ticket_growth_rate(),
            'monthly_new_users_growth_rate': calculate_monthly_new_users_growth_rate(),
            'monthly_churn_rate_growth_rate': calculate_monthly_churn_rate_growth_rate(),
            'monthly_satisfaction_rate_growth_rate': calculate_monthly_satisfaction_rate_growth_rate(),
            'monthly_revenue_growth_rate': calculate_monthly_revenue_growth_rate(),
            'monthly_active_user_growth_rate': calculate_monthly_active_user_growth_rate(),
            'monthly_threat_detection_growth_rate': calculate_monthly_threat_detection_growth_rate(),
            'monthly_device_protection_growth_rate': calculate_monthly_device_protection_growth_rate(),
            'monthly_support_ticket_growth_rate': calculate_monthly_support_ticket_growth_rate(),
            'monthly_new_users_growth_rate': calculate_monthly_new_users_growth_rate(),
            'monthly_churn_rate_growth_rate': calculate_monthly_churn_rate_growth_rate(),
            'monthly_satisfaction_rate_growth_rate': calculate_monthly_satisfaction_rate_growth_rate(),
            'monthly_revenue_growth_rate': calculate_monthly_revenue_growth_rate(),
            'monthly_active_user_growth_rate': calculate_monthly_active_user_growth_rate(),
            'monthly_threat_detection_growth_rate': calculate_monthly_threat_detection_growth_rate(),
            'monthly_device_protection_growth_rate': calculate_monthly_device_protection_growth_rate(),
            'monthly_support_ticket_growth_rate': calculate_monthly_support_ticket_growth_rate(),
            'monthly_new_users_growth_rate': calculate_monthly_new_users_growth_rate(),
            'monthly_churn_rate_growth_rate': calculate_monthly_churn_rate_growth_rate(),
            'monthly_satisfaction_rate_growth_rate': calculate_monthly_satisfaction_rate_growth_rate(),
            'monthly_revenue_growth_rate': calculate_monthly_revenue_growth_rate(),
            'monthly_active_user_growth_rate': calculate_monthly_active_user_growth_rate(),
            'monthly_threat_detection_growth_rate': calculate_monthly_threat_detection_growth_rate(),
            'monthly_device_protection_growth_rate': calculate_monthly_device_protection_growth_rate(),

            'monthly_new_users': calculate_monthly_new_users()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500