from flask import Blueprint, jsonify, request
from models import User, Device, Threat, Alert
from extensions import db
from datetime import datetime, timedelta

api = Blueprint('api', __name__)

@api.route('/api/stats/overview')
def get_overview_stats():
    return jsonify({
        'total_users': User.query.count(),
        'total_devices': Device.query.count(),
        'total_threats': Threat.query.count(),
        'active_alerts': Alert.query.filter_by(read=False).count()
    })

@api.route('/api/stats/threats')
def get_threat_stats():
    week_ago = datetime.now() - timedelta(days=7)
    return jsonify({
        'total': Threat.query.count(),
        'active': Threat.query.filter_by(status='Active').count(),
        'resolved': Threat.query.filter_by(status='Resolved').count(),
        'recent': Threat.query.filter(Threat.created_at >= week_ago).count()
    })

@api.route('/api/stats/devices')
def get_device_stats():
    return jsonify({
        'total': Device.query.count(),
        'online': Device.query.filter_by(status='online').count(),
        'offline': Device.query.filter_by(status='offline').count(),
        'maintenance': Device.query.filter_by(status='maintenance').count()
    })

@api.route('/api/notifications/unread')
def get_unread_notifications():
    user_id = request.args.get('user_id')
    alerts = Alert.query.filter_by(user_id=user_id, read=False).all()
    return jsonify([alert.to_dict() for alert in alerts])


@api.route('/api/stats/security')
def get_security_stats():
    try:
        now = datetime.now()
        week_ago = now - timedelta(days=7)
        
        # Get threat severity distribution
        severity_stats = db.session.query(
            Threat.severity,
            db.func.count(Threat.id).label('count')
        ).group_by(Threat.severity).all()
        
        # Get recent security incidents
        recent_incidents = Alert.query.filter(
            Alert.type == 'security',
            Alert.created_at >= week_ago
        ).order_by(Alert.created_at.desc()).limit(10).all()
        
        # Get vulnerability trends
        daily_vulnerabilities = db.session.query(
            db.func.date(Threat.created_at).label('date'),
            db.func.count(Threat.id).label('count')
        ).filter(
            Threat.type == 'vulnerability',
            Threat.created_at >= week_ago
        ).group_by(db.func.date(Threat.created_at)).all()
        
        return jsonify({
            'severity_distribution': dict(severity_stats),
            'recent_incidents': [incident.to_dict() for incident in recent_incidents],
            'vulnerability_trends': [
                {'date': str(v.date), 'count': v.count}
                for v in daily_vulnerabilities
            ],
            'timestamp': now.isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/stats/performance')
def get_performance_stats():
    try:
        # Get system performance metrics
        system_metrics = get_system_metrics()
        
        # Get network performance
        network_stats = get_network_stats()
        
        # Get response time metrics
        response_times = get_response_time_metrics()
        
        return jsonify({
            'system': system_metrics,
            'network': network_stats,
            'response_times': response_times,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/alerts/summary')
def get_alert_summary():
    try:
        now = datetime.now()
        today = now.date()
        
        # Get alert statistics
        total_alerts = Alert.query.count()
        unread_alerts = Alert.query.filter_by(read=False).count()
        today_alerts = Alert.query.filter(
            Alert.created_at >= today
        ).count()
        
        # Get alerts by severity
        severity_distribution = db.session.query(
            Alert.severity,
            db.func.count(Alert.id).label('count')
        ).group_by(Alert.severity).all()
        
        # Get recent critical alerts
        critical_alerts = Alert.query.filter_by(
            severity='critical',
            read=False
        ).order_by(Alert.created_at.desc()).limit(5).all()
        
        return jsonify({
            'total': total_alerts,
            'unread': unread_alerts,
            'today': today_alerts,
            'severity_distribution': dict(severity_distribution),
            'critical_alerts': [alert.to_dict() for alert in critical_alerts],
            'timestamp': now.isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500