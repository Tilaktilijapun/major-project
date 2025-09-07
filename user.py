from flask import Blueprint, render_template, session, jsonify, request, redirect, url_for, Flask
from models import User, Alert, ActivityLog, DeviceActivityLog
from extensions import db
from datetime import datetime, timedelta
from sqlalchemy import desc
from flask_login import login_required, current_user


user = Blueprint('user', __name__)

@user.route('/user-dashboard')
def user_dashboard():
    user_id = session.get('user_id')
    user_data = User.query.get_or_404(user_id)
    alerts = Alert.query.filter_by(user_id=user_id).order_by(Alert.created_at.desc()).all()
    return render_template('user-dashboard.html', user=user_data, alerts=alerts)

@user.route('/user-profile')
def profile():  # Change function name from user_profile to profile
    user_id = session.get('user_id')
    user_data = User.query.get_or_404(user_id)
    return render_template('user-profile.html', user=user_data)

@user.route('/user-activity')
def user_activity():
    user_id = session.get('user_id')
    activities = Alert.query.filter_by(user_id=user_id).order_by(Alert.created_at.desc()).all()

    logs = (
        DeviceActivityLog.query
        .filter_by(user_id=current_user.id)
        .order_by(DeviceActivityLog.timestamp.desc())
        .limit(20)
        .all()
    )

    activities = [
        {
            'time': log.time.strftime('%Y-%m-%d %H:%M:%S'),
            'activity': log.activity,
            'location': log.location or 'Unknown',
            'status': log.status
        }
        for log in logs
    ]

    suspicious = DeviceActivityLog.query.filter_by(
        user_id=current_user.id,
        status='Suspicious'
    ).count()

    failed_logins = DeviceActivityLog.query.filter(
        DeviceActivityLog.user_id == current_user.id,
        DeviceActivityLog.activity.ilike('%failed login%')
    ).count()

    data_dashboard = {
        'suspicious': suspicious,
        'failed_logins': failed_logins
    }

    return render_template(
        'activity-log.html',
        activity_logs=activities,
        data_dashboard=data_dashboard
    )

@user.route('/api/user/update-profile', methods=['PUT'])
def update_profile():
    try:
        user_id = session.get('user_id')
        user_data = User.query.get_or_404(user_id)
        data = request.json

        if 'username' in data:
            user_data.username = data['username']
        if 'email' in data:
            user_data.email = data['email']
        if 'password' in data:
            user_data.set_password(data['password'])

        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user.route('/api/user/activities')
def get_user_activities():
    try:
        user_id = session.get('user_id')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        activities = Alert.query.filter_by(user_id=user_id)\
            .order_by(Alert.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'activities': [activity.to_dict() for activity in activities.items],
            'total': activities.total,
            'pages': activities.pages,
            'current_page': activities.page
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user.route('/api/user/notifications/settings', methods=['PUT'])
def update_notification_settings():
    try:
        user_id = session.get('user_id')
        user_data = User.query.get_or_404(user_id)
        data = request.json

        user_data.notification_settings = data.get('settings', {})
        db.session.commit()
        return jsonify({'message': 'Notification settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user.route('/api/user/dashboard/summary')
def get_dashboard_summary():
    try:
        user_id = session.get('user_id')
        
        # Get user's recent alerts
        recent_alerts = Alert.query.filter_by(user_id=user_id)\
            .order_by(Alert.created_at.desc())\
            .limit(5).all()
        
        # Get user's activity statistics
        total_activities = Alert.query.filter_by(user_id=user_id).count()
        recent_activities = Alert.query.filter_by(
            user_id=user_id
        ).filter(
            Alert.created_at >= (datetime.now() - timedelta(days=7))
        ).count()
        
        # Get user's security status
        security_status = {
            'last_login': session.get('last_login'),
            'active_sessions': Session.query.filter_by(user_id=user_id, active=True).count(),
            'security_level': User.query.get(user_id).security_level
        }
        
        return jsonify({
            'recent_alerts': [alert.to_dict() for alert in recent_alerts],
            'activity_stats': {
                'total': total_activities,
                'recent': recent_activities
            },
            'security_status': security_status
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user.route('/api/user/security/settings', methods=['GET', 'PUT'])
def manage_security_settings():
    try:
        user_id = session.get('user_id')
        user_data = User.query.get_or_404(user_id)
        
        if request.method == 'GET':
            return jsonify({
                'two_factor_enabled': user_data.two_factor_enabled,
                'security_questions': user_data.security_questions,
                'notification_preferences': user_data.notification_preferences
            })
        
        data = request.json
        user_data.two_factor_enabled = data.get('two_factor_enabled', user_data.two_factor_enabled)
        user_data.security_questions = data.get('security_questions', user_data.security_questions)
        user_data.notification_preferences = data.get('notification_preferences', user_data.notification_preferences)
        
        db.session.commit()
        return jsonify({'message': 'Security settings updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@user.route('/api/user/security/reset-password', methods=['POST'])
def reset_password():
        try:
            user_id = session.get('user_id')
            user_data = User.query.get_or_404(user_id)
            data = request.json
            
            # Validate current password
            if not user_data.check_password(data['current_password']):
                return jsonify({'error': 'Current password is incorrect'}), 400
            
            # Set new password
            user_data.set_password(data['new_password'])
            db.session.commit()
            return jsonify({'message': 'Password reset successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
@user.route('/api/user/security/change-password', methods=['POST'])
def change_password():
    try:
        user_id = session.get('user_id')
        user_data = User.query.get_or_404(user_id)
        data = request.json
        
        # Validate current password
        if not user_data.check_password(data['current_password']):
            return jsonify({'error': 'Current password is incorrect'}), 400
        
        # Set new password
        user_data.set_password(data['new_password'])
        db.session.commit()
        return jsonify({'message': 'Password changed successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



    