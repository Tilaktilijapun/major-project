from flask import Blueprint, jsonify, request
from models import Notification, User, NotificationPreference
from datetime import datetime
from extensions import db

notifications_bp = Blueprint('notifications', __name__)

@notifications_bp.route('/api/notifications/preferences', methods=['GET', 'PUT'])
def manage_notification_preferences():
    try:
        user_id = request.args.get('user_id')
        
        if request.method == 'GET':
            preferences = NotificationPreference.query.filter_by(user_id=user_id).first()
            
            if not preferences:
                return jsonify({'error': 'Preferences not found'}), 404
                
            return jsonify({
                'status': 'success',
                'data': {
                    'email_enabled': preferences.email_enabled,
                    'push_enabled': preferences.push_enabled,
                    'sms_enabled': preferences.sms_enabled,
                    'alert_types': preferences.alert_types,
                    'quiet_hours': {
                        'start': preferences.quiet_hours_start,
                        'end': preferences.quiet_hours_end
                    }
                }
            }), 200
            
        elif request.method == 'PUT':
            data = request.get_json()
            preferences = NotificationPreference.query.filter_by(user_id=user_id).first()
            
            if not preferences:
                preferences = NotificationPreference(user_id=user_id)
                
            preferences.email_enabled = data.get('email_enabled', preferences.email_enabled)
            preferences.push_enabled = data.get('push_enabled', preferences.push_enabled)
            preferences.sms_enabled = data.get('sms_enabled', preferences.sms_enabled)
            preferences.alert_types = data.get('alert_types', preferences.alert_types)
            preferences.quiet_hours_start = data.get('quiet_hours_start', preferences.quiet_hours_start)
            preferences.quiet_hours_end = data.get('quiet_hours_end', preferences.quiet_hours_end)
            
            db.session.add(preferences)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': 'Preferences updated successfully'
            }), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/api/notifications/user/<user_id>')

def get_user_notifications(user_id):
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        notifications = Notification.query.filter_by(user_id=user_id)\
            .order_by(Notification.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'notifications': [notif.to_dict() for notif in notifications.items],
            'unread_count': Notification.query.filter_by(user_id=user_id, read=False).count(),
            'total': notifications.total,
            'pages': notifications.pages,
            'current_page': notifications.page
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/api/notifications/mark-read', methods=['POST'])
def mark_notifications_read():
    try:
        data = request.get_json()
        notification_ids = data.get('notification_ids', [])
        
        if not notification_ids:
            return jsonify({'error': 'No notification IDs provided'}), 400
            
        notifications = Notification.query.filter(Notification.id.in_(notification_ids)).all()
        for notification in notifications:
            notification.read = True
            notification.read_at = datetime.now()
            
        db.session.commit()
        
        return jsonify({
            'message': 'Notifications marked as read',
            'updated_count': len(notifications)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@notifications_bp.route('/send_notifications', methods=['POST'])
def send_notifications():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        message = data.get('message')
        alert_type = data.get('alert_type')
        timestamp = data.get('timestamp')

        if not user_id or not message or not alert_type or not timestamp:
            return jsonify({'error': 'Missing required fields'}), 400

        user = User.query.get(user_id)
        preferences = NotificationPreference.query.filter_by(user_id=user_id).first()
        if not preferences:
            return jsonify({'error': 'User preferences not found'}), 404
        if alert_type not in preferences.alert_types:
            return jsonify({'error': 'Alert type not enabled for user'}), 400
        if preferences.quiet_hours_start and preferences.quiet_hours_end:
            now = datetime.now().time()
            if preferences.quiet_hours_start <= now <= preferences.quiet_hours_end:
                return jsonify({'error': 'Quiet hours, no notifications allowed'}), 401
        if not user:
            return jsonify({'error': 'User not found'}), 404
        if not user.email and not user.phone_number:
            return jsonify({'error': 'User has no contact information'}), 400
        notification = Notification(
            user_id=user_id,
            message=message,
            alert_type=alert_type,
            timestamp=timestamp
        )
        db.session.add(notification)
        db.session.commit()
        return jsonify({'message': 'Notification sent'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
