from flask import Flask, Blueprint, jsonify, request, url_for, session, render_template
from models import PricingPlans, Subscription
from extensions import db
import datetime
from flask_login import current_user, login_required
from user_dashboard import user_dashboard_bp
from user import user as user_bp
from user_profile import user_profile_bp
from uuid import UUID

app = Flask(__name__,
          template_folder='../templates',
          static_folder='../static',
          static_url_path='/static')

pricing_bp = Blueprint('pricing', __name__)

@app.route('/pricing')
@login_required
def pricing():
    return render_template('pricing.html')


app.register_blueprint(user_dashboard_bp, url_prefix='/dashboard')  # Add url_prefix
app.register_blueprint(user_bp, url_prefix='/user')  # Use the renamed blueprint
app.register_blueprint(user_profile_bp, url_prefix='/profile')  # Add url_prefix for user profile routes

@pricing_bp.route('/api/pricing/plans', methods=['GET'])
def get_pricing_plans():
    try:
        plans = PricingPlans.query.all()
        return jsonify({
            'status': 'success',
            'plans': [{
                'id': plan.id,
                'name': plan.name,
                'price': plan.price,
                'billing_cycle': plan.billing_cycle,
                'features': plan.features,
                'description': plan.description,
                'duration_days': plan.duration_days,
                'status': plan.status,
                'created_at': plan.created_at.isoformat()
            } for plan in plans]
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@pricing_bp.route('/api/pricing/subscribe', methods=['POST'])
def subscribe_to_plan():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        plan_id = data.get('plan_id')
        
        if not user_id or not plan_id:
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields'
            }), 400
            
        plan = PricingPlans.query.get(plan_id)
        if not plan:
            return jsonify({
                'status': 'error',
                'message': 'Invalid plan ID'
            }), 404
            
        subscription = Subscription(
            user_id=user_id,
            plan_id=plan_id,
            start_date=datetime.utcnow()
        )
        
        db.session.add(subscription)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Successfully subscribed to plan',
            'subscription': {
                'id': subscription.id,
                'user_id': subscription.user_id,
                'plan_id': subscription.plan_id,
                'start_date': subscription.start_date.isoformat()
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@pricing_bp.route('/api/pricing/subscription/<uuid:user_id>', methods=['GET'])
def get_user_subscription(user_id: UUID):
    try:
        # Convert UUID to string before comparing
        subscription = Subscription.query.filter_by(user_id=str(user_id)).first()

        if not subscription:
            return jsonify({
                'status': 'error',
                'message': 'No active subscription found'
            }), 404

        plan = PricingPlans.query.get(subscription.plan_id)
        
        return jsonify({
            'status': 'success',
            'subscription': {
                'id': subscription.id,
                'plan': {
                    'id': plan.id,
                    'name': plan.name,
                    'price': plan.price,
                    'features': plan.features
                },
                'start_date': subscription.start_date.isoformat()
            }
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500