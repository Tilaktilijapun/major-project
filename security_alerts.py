from flask import Blueprint, jsonify, request, render_template
from datetime import datetime
from models import Alert
from extensions import db
from ml_features import predict_threat_level
from flask_login import login_required, current_user
import uuid
import logging

alerts_bp = Blueprint('alerts', __name__)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s - RequestID: %(request_id)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z'
)
logging.getLogger().addFilter(lambda record: setattr(record, 'request_id', str(uuid.uuid4())) or True)

@alerts_bp.route('/user/security_alerts', endpoint='user_security_alerts')
@login_required
def security_alerts_page():
    """Renders the security alerts dashboard page."""
    return render_template('security-alerts.html')

def create_alert(title, message, user_id=None, threat_id=None, false_positive=False, features=None):
    """Creates a new alert and classifies severity/category if ML features provided."""
    request_id = str(uuid.uuid4())
    severity = None
    category = None

    if features:
        try:
            prediction = predict_threat_level(features)
            severity = prediction.get('severity')
            category = prediction.get('category')
            logging.debug(f"Threat level predicted: severity={severity}, category={category}, RequestID: {request_id}")
        except Exception as e:
            logging.error(f"[ML ERROR] Threat classification failed: {e}, RequestID: {request_id}")

    new_alert = Alert(
        id=str(uuid.uuid4()),
        title=title,
        message=message,
        user_id=user_id or str(current_user.id),
        threat_id=threat_id,
        created_at=datetime.now(datetime.timezone.utc),
        read=False,
        false_positive=false_positive,
        severity=severity,
        category=category
    )

    try:
        db.session.add(new_alert)
        db.session.commit()
        logging.debug(f"Alert created: {title}, RequestID: {request_id}")
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating alert: {e}, RequestID: {request_id}")
        raise
    return new_alert

@alerts_bp.route('/alerts', methods=['GET'])
@login_required
def get_alerts():
    """Fetch all alerts for the current user."""
    request_id = str(uuid.uuid4())
    try:
        alerts = Alert.query.filter_by(user_id=str(current_user.id)).order_by(Alert.created_at.desc()).all()
        logging.debug(f"Fetched {len(alerts)} alerts for user {current_user.id}, RequestID: {request_id}")
        return jsonify([alert.to_dict() for alert in alerts])
    except Exception as e:
        logging.error(f"Error fetching alerts: {e}, RequestID: {request_id}")
        return jsonify({'error': f'Failed to fetch alerts: {str(e)}', 'request_id': request_id}), 500

@alerts_bp.route('/alerts/create', methods=['POST'])
@login_required
def create_new_alert():
    """API to create a new alert."""
    request_id = str(uuid.uuid4())
    try:
        data = request.json
        if not data or 'title' not in data or 'message' not in data:
            logging.error(f"Missing required fields, RequestID: {request_id}")
            return jsonify({'error': 'Missing required fields', 'request_id': request_id}), 400

        alert = create_alert(
            title=data['title'],
            message=data['message'],
            user_id=str(current_user.id),
            threat_id=data.get('threat_id'),
            false_positive=data.get('false_positive', False),
            features=data.get('features')
        )
        logging.debug(f"Alert created successfully for user {current_user.id}, RequestID: {request_id}")
        return jsonify({'message': 'Alert created successfully', 'alert': alert.to_dict(), 'request_id': request_id}), 201
    except Exception as e:
        logging.error(f"Error creating new alert: {e}, RequestID: {request_id}")
        return jsonify({'error': f'Failed to create alert: {str(e)}', 'request_id': request_id}), 500

@alerts_bp.route('/alerts/<string:alert_id>/mark_read', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    """Mark an alert as read."""
    request_id = str(uuid.uuid4())
    try:
        alert = Alert.query.get_or_404(str(alert_id))
        if alert.user_id != str(current_user.id):
            logging.error(f"Unauthorized access to alert {alert_id} by user {current_user.id}, RequestID: {request_id}")
            return jsonify({'error': 'Unauthorized', 'request_id': request_id}), 403

        alert.read = True
        db.session.commit()
        logging.debug(f"Alert {alert_id} marked as read for user {current_user.id}, RequestID: {request_id}")
        return jsonify({'message': 'Alert marked as read', 'request_id': request_id})
    except Exception as e:
        logging.error(f"Error marking alert as read: {e}, RequestID: {request_id}")
        return jsonify({'error': f'Failed to mark alert as read: {str(e)}', 'request_id': request_id}), 500

@alerts_bp.route('/alerts/<string:alert_id>/mark_false_positive', methods=['POST'])
@login_required
def mark_false_positive(alert_id):
    """Mark an alert as false positive."""
    request_id = str(uuid.uuid4())
    try:
        alert = Alert.query.get_or_404(str(alert_id))
        if alert.user_id != str(current_user.id):
            logging.error(f"Unauthorized access to alert {alert_id} by user {current_user.id}, RequestID: {request_id}")
            return jsonify({'error': 'Unauthorized', 'request_id': request_id}), 403

        alert.false_positive = True
        db.session.commit()
        logging.debug(f"Alert {alert_id} marked as false positive for user {current_user.id}, RequestID: {request_id}")
        return jsonify({'message': 'Alert marked as false positive', 'request_id': request_id})
    except Exception as e:
        logging.error(f"Error marking alert as false positive: {e}, RequestID: {request_id}")
        return jsonify({'error': f'Failed to mark alert as false positive: {str(e)}', 'request_id': request_id}), 500

@alerts_bp.route('/alerts/<string:alert_id>/delete', methods=['DELETE'])
@login_required
def delete_alert(alert_id):
    """Delete an alert."""
    request_id = str(uuid.uuid4())
    try:
        alert = Alert.query.get_or_404(str(alert_id))
        if alert.user_id != str(current_user.id):
            logging.error(f"Unauthorized access to alert {alert_id} by user {current_user.id}, RequestID: {request_id}")
            return jsonify({'error': 'Unauthorized', 'request_id': request_id}), 403

        db.session.delete(alert)
        db.session.commit()
        logging.debug(f"Alert {alert_id} deleted for user {current_user.id}, RequestID: {request_id}")
        return jsonify({'message': 'Alert deleted', 'request_id': request_id})
    except Exception as e:
        logging.error(f"Error deleting alert: {e}, RequestID: {request_id}")
        return jsonify({'error': f'Failed to delete alert: {str(e)}', 'request_id': request_id}), 500
