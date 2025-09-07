from flask import current_app, render_template, jsonify, request, Blueprint
from flask_login import login_required, current_user
from datetime import datetime
from models import ActivityLog, User
from sqlalchemy import func
from extensions import db
from functools import wraps
from flask import request

user_activity_bp = Blueprint('user_activity', __name__)

@user_activity_bp.route('/')
@login_required
def user_activity():
    return render_template('activity-log.html')


def log_user_activity(user_id, activity_type, description, ip_address=None):
    """
    Log a user activity in the system.
    Args:
        user_id: The ID of the user performing the activity
        activity_type: Type of activity (e.g., 'login', 'logout', 'profile_update')
        description: Detailed description of the activity
        ip_address: IP address of the user (optional)
    Returns:
        ActivityLog: The created activity log instance
    """
    try:
        activity_log = ActivityLog(
            user_id=user_id,
            activity_type=activity_type,
            description=description,
            ip_address=ip_address,
            timestamp=datetime.utcnow()
        )
        db.session.add(activity_log)
        db.session.commit()
        return activity_log
    except Exception as e:
        current_app.logger.error(f"Error logging user activity: {str(e)}")
        db.session.rollback()
        return None

def get_user_activities(user_id, limit=50, offset=0, activity_type=None):
    """
    Retrieve user activities with optional filtering and pagination.
    Args:
        user_id: The ID of the user whose activities to retrieve
        limit: Maximum number of activities to return (default: 50)
        offset: Number of activities to skip (default: 0)
        activity_type: Filter activities by type (optional)
    Returns:
        list: List of activity logs
    """
    query = ActivityLog.query.filter_by(user_id=user_id)
    
    if activity_type:
        query = query.filter_by(activity_type=activity_type)
    
    return query.order_by(ActivityLog.timestamp.desc()).offset(offset).limit(limit).all()

def get_recent_activities(hours=24):
    """
    Get recent activities across all users within the specified time period.
    Args:
        hours: Number of hours to look back (default: 24)
    Returns:
        list: List of recent activity logs
    """
    from datetime import timedelta
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    return ActivityLog.query\
        .join(User)\
        .filter(ActivityLog.timestamp >= cutoff_time)\
        .order_by(ActivityLog.timestamp.desc())\
        .all()

def get_user_activity_summary(user_id):
    """
    Get a summary of user activities grouped by type.
    Args:
        user_id: The ID of the user
    Returns:
        dict: Dictionary containing activity counts by type
    """
    from sqlalchemy import func
    
    activities = db.session.query(
        ActivityLog.activity_type,
        func.count(ActivityLog.id).label('count')
    ).filter_by(user_id=user_id)\
    .group_by(ActivityLog.activity_type)\
    .all()
    
    return {activity.activity_type: activity.count for activity in activities}

def clear_old_activities(days=30):
    """
    Remove activity logs older than the specified number of days.
    Args:
        days: Number of days to keep logs for (default: 30)
    Returns:
        int: Number of records deleted
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        deleted = ActivityLog.query.filter(ActivityLog.timestamp < cutoff_date).delete()
        db.session.commit()
        return deleted
    except Exception as e:
        current_app.logger.error(f"Error clearing old activities: {str(e)}")
        db.session.rollback()
        return 0

@user_activity_bp.route('/api/logs')
@login_required
def get_logs():
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        activity_type = request.args.get('activity_type')

        logs = get_user_activities(current_user.id, limit=limit, offset=offset, activity_type=activity_type)
        
        return jsonify([
            {
                'id': log.id,
                'activity_type': log.activity_type,
                'description': log.description,
                'ip_address': log.ip_address,
                'timestamp': log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            } for log in logs
        ])
    except Exception as e:
        current_app.logger.error(f"Error fetching user logs: {str(e)}")
        return jsonify({'error': 'Unable to fetch logs'}), 500

@user_activity_bp.route('/api/summary')
@login_required
def get_summary():
    try:
        summary = get_user_activity_summary(current_user.id)
        return jsonify(summary)
    except Exception as e:
        current_app.logger.error(f"Error fetching user activity summary: {str(e)}")
        return jsonify({'error': 'Unable to fetch summary'}), 500

def log_activity(activity_type, description=""):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip_address = request.remote_addr
            log_user_activity(
                user_id=current_user.id if current_user.is_authenticated else None,
                activity_type=activity_type,
                description=description,
                ip_address=ip_address
            )
            return f(*args, **kwargs)
        return wrapper
    return decorator