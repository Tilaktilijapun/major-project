from flask import Blueprint, jsonify, render_template, redirect, url_for
from flask_login import login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import json
import logging
from uuid import uuid4
from sqlalchemy.sql import func
from sqlalchemy.exc import DatabaseError
from extensions import db
from system_metrics import (
    get_cpu_usage, get_memory_usage, get_disk_usage, get_network_stats,
    get_system_temperature, get_system_info, get_network_io, get_cpu_times,
    get_memory_info, get_disk_io_info, get_network_details
)
from models import SecurityScanResult, SecurityAlert, Threat, AccessRequest
import psutil
from monitoring import monitor_instance

user_dashboard_bp = Blueprint('user_dashboard', __name__)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s - RequestID: %(request_id)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z'
)
logging.getLogger().addFilter(lambda record: setattr(record, 'request_id', str(uuid4())) or True)

# Configure rate limiter
limiter = Limiter(key_func=get_remote_address)

# Valid severities and threat types
VALID_SEVERITIES = ['Critical', 'High', 'Medium', 'Low']
THREAT_TYPES = ['malware', 'phishing', 'ddos', 'sql_injection', 'brute_force']

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for handling datetime and other non-serializable objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def calculate_risk_score(severity_counts):
    """Calculate a risk score based on severity counts."""
    try:
        score = (
            severity_counts.get('critical', 0) * 40 +
            severity_counts.get('high', 0) * 20 +
            severity_counts.get('medium', 0) * 10 +
            severity_counts.get('low', 0) * 5
        )
        return min(score, 100)
    except Exception as e:
        logging.error(f"Error calculating risk score: {e}")
        return 0

def get_system_stats():
    """Retrieve latest system metrics from monitoring.py and psutil."""
    try:
        stats = {}
        if monitor_instance and monitor_instance.latest_system_metrics:
            stats = monitor_instance.latest_system_metrics
        # Supplement with psutil metrics
        stats.update({
            'cpu': round(psutil.cpu_percent(interval=1), 1),
            'memory': round(psutil.virtual_memory().percent, 1),
            'disk': round(psutil.disk_usage('/').percent, 1),
            'uptime': int(psutil.boot_time()),
            'network': get_network_io()
        })
        return stats
    except Exception as e:
        logging.error(f"Error fetching system metrics: {e}")
        return {'cpu': 0, 'memory': 0, 'disk': 0, 'uptime': 0, 'network': {}}

def get_network_activity():
    """Retrieve network activity data for the last 7 intervals."""
    try:
        network_data = []
        counters = psutil.net_io_counters()
        now = datetime.utcnow()
        for i in range(7):
            network_data.append({
                'time': (now - timedelta(minutes=i*5)).strftime('%H:%M'),
                'bytes_sent': counters.bytes_sent // (1024*1024),  # Convert to MB
                'bytes_received': counters.bytes_recv // (1024*1024)  # Convert to MB
            })
        return network_data[::-1]  # Reverse to show most recent first
    except Exception as e:
        logging.error(f"Error fetching network activity: {e}")
        return [{'time': (now - timedelta(minutes=i*5)).strftime('%H:%M'), 'bytes_sent': 0, 'bytes_received': 0} for i in range(7)]

@user_dashboard_bp.route('/dashboard')
@login_required
def user_dashboard():
    """Render the user dashboard page."""
    return render_template('user-dashboard.html')

@user_dashboard_bp.route('/api/dashboard-data')
@login_required
@limiter.limit("10 per minute")
def dashboard_data():
    """Fetch dashboard data."""
    request_id = str(uuid4())
    user_id = str(current_user.id)
    logging.debug(f"Fetching dashboard data for user {user_id}, RequestID: {request_id}")
    now = datetime.utcnow()

    try:
        # System Metrics
        system_stats = get_system_stats()

        # Security Stats
        def get_active_threats(days):
            try:
                count = Threat.query.filter(
                    Threat.detected_at >= now - timedelta(days=days),
                    Threat.status == 'Active',
                    Threat.affected_device.in_(
                        db.session.query(SecurityScanResult.user_id).filter_by(user_id=user_id)
                    )
                ).count()
                logging.debug(f"Active threats query executed for user {user_id}, days={days}, count={count}, RequestID: {request_id}")
                return count
            except DatabaseError as e:
                logging.error(f"Error querying active threats for {days} days: {e}, RequestID: {request_id}")
                db.session.rollback()
                return 0

        try:
            severity_counts = {
                lvl.lower(): Threat.query.filter_by(
                    severity=lvl,
                    affected_device=db.session.query(SecurityScanResult.user_id).filter_by(user_id=user_id)
                ).count() for lvl in VALID_SEVERITIES
            }
            logging.debug(f"Severity counts retrieved: {severity_counts}, RequestID: {request_id}")
        except DatabaseError as e:
            logging.error(f"Error querying severity counts: {e}, RequestID: {request_id}")
            db.session.rollback()
            severity_counts = {lvl.lower(): 0 for lvl in VALID_SEVERITIES}

        try:
            threat_types = {
                ttype: Threat.query.filter(
                    Threat.type.ilike(f'%{ttype}%'),
                    Threat.affected_device.in_(
                        db.session.query(SecurityScanResult.user_id).filter_by(user_id=user_id)
                    )
                ).count() for ttype in THREAT_TYPES
            }
            logging.debug(f"Threat types retrieved: {threat_types}, RequestID: {request_id}")
        except DatabaseError as e:
            logging.error(f"Error querying threat types: {e}, RequestID: {request_id}")
            db.session.rollback()
            threat_types = {ttype: 0 for ttype in THREAT_TYPES}

        # Threat Trend
        try:
            threat_trend = []
            for i in range(7):
                date = (now - timedelta(days=i)).date()
                count = Threat.query.filter(
                    func.date(Threat.detected_at) == date,
                    Threat.affected_device.in_(
                        db.session.query(SecurityScanResult.user_id).filter_by(user_id=user_id)
                    )
                ).count()
                threat_trend.append({'date': date.strftime('%Y-%m-%d'), 'count': count})
            logging.debug(f"Threat trend retrieved: {threat_trend}, RequestID: {request_id}")
        except DatabaseError as e:
            logging.error(f"Error building threat trend: {e}, RequestID: {request_id}")
            db.session.rollback()
            threat_trend = [{'date': (now - timedelta(days=i)).date().strftime('%Y-%m-%d'), 'count': 0} for i in range(7)]

        # Security Metrics
        try:
            security_metrics = {
                'firewall': round(psutil.cpu_percent(interval=0.1) * 0.8 + 20, 1),
                'intrusion': round(psutil.virtual_memory().percent * 0.6 + 30, 1),
                'patch_compliance': round(psutil.disk_usage('/').percent * 0.7 + 25, 1),
                'encryption': round((system_stats.get('uptime', 0) % 100) * 0.9 + 10, 1),
                'authentication': round((system_stats.get('cpu', 0) + system_stats.get('memory', 0)) / 2 * 0.85, 1)
            }
        except Exception as e:
            logging.error(f"Error calculating security metrics: {e}, RequestID: {request_id}")
            security_metrics = {
                'firewall': 80,
                'intrusion': 60,
                'patch_compliance': 90,
                'encryption': 75,
                'authentication': 85
            }

        # Risk Score
        risk_score = calculate_risk_score(severity_counts)
        risk_score_breakdown = {
            'network': min(severity_counts.get('critical', 0) * 10 + severity_counts.get('high', 0) * 5, 100),
            'application': min(severity_counts.get('medium', 0) * 8 + severity_counts.get('low', 0) * 2, 100),
            'user_behavior': min(severity_counts.get('medium', 0) * 5, 100),
            'system': min(severity_counts.get('high', 0) * 3 + severity_counts.get('low', 0) * 2, 100)
        }

        # Recent Threats
        try:
            recent_threats = Threat.query.filter(
                Threat.affected_device.in_(
                    db.session.query(SecurityScanResult.user_id).filter_by(user_id=user_id)
                )
            ).order_by(Threat.detected_at.desc()).limit(5).all()
            recent_threats_list = [{
                'id': threat.id,
                'name': threat.name,
                'type': threat.type,
                'description': threat.description,
                'severity': threat.severity,
                'detected_at': threat.detected_at.isoformat(),
                'ip_address': threat.ip_address,
                'port': threat.port,
                'protocol': threat.protocol,
                'indicator': threat.indicator,
                'recommended_action': threat.recommended_action
            } for threat in recent_threats]
            logging.debug(f"Recent threats retrieved: {len(recent_threats_list)} threats, RequestID: {request_id}")
        except DatabaseError as e:
            logging.error(f"Error querying recent threats: {e}, RequestID: {request_id}")
            db.session.rollback()
            recent_threats_list = []

        # Threat Timeline
        try:
            threat_timeline = [
                {
                    'type': threat.type,
                    'timestamp': threat.detected_at.isoformat(),
                    'description': f"{threat.description or 'No description'} (IP: {threat.ip_address or 'N/A'}, Port: {threat.port or 'N/A'}, Protocol: {threat.protocol or 'N/A'})",
                    'severity': threat.severity,
                    'name': threat.name,
                    'ip_address': threat.ip_address,
                    'port': threat.port,
                    'protocol': threat.protocol
                } for threat in Threat.query.filter(
                    Threat.affected_device.in_(
                        db.session.query(SecurityScanResult.user_id).filter_by(user_id=user_id)
                    )
                ).order_by(Threat.detected_at.desc()).limit(5).all()
            ]
            logging.debug(f"Threat timeline built: {len(threat_timeline)} items, RequestID: {request_id}")
        except Exception as e:
            logging.error(f"Error building threat timeline: {e}, RequestID: {request_id}")
            db.session.rollback()
            threat_timeline = []

        # Recent Alerts
        try:
            recent_alerts = SecurityAlert.query.filter_by(user_id=user_id)\
                .order_by(SecurityAlert.created_at.desc()).limit(5).all()
            recent_alerts_list = [alert.to_dict() for alert in recent_alerts]
            logging.debug(f"Recent alerts retrieved: {len(recent_alerts_list)} alerts, RequestID: {request_id}")
        except DatabaseError as e:
            logging.error(f"Error querying recent alerts: {e}, RequestID: {request_id}")
            db.session.rollback()
            recent_alerts_list = []

        # Access Requests
        try:
            access_requests = AccessRequest.query.filter_by(user_id=user_id, status='Pending')\
                .order_by(AccessRequest.created_at.desc()).limit(5).all()
            access_requests_list = [
                {
                    'id': request.id,
                    'device': request.device_name,
                    'ip_address': request.ip_address,
                    'timestamp': request.created_at.isoformat(),
                    'description': request.description or 'No description provided'
                } for request in access_requests
            ]
            logging.debug(f"Access requests retrieved: {len(access_requests_list)} requests, RequestID: {request_id}")
        except DatabaseError as e:
            logging.error(f"Error querying access requests: {e}, RequestID: {request_id}")
            db.session.rollback()
            access_requests_list = []

        # Recent Scans
        try:
            recent_scans = SecurityScanResult.query.filter_by(user_id=user_id)\
                .order_by(SecurityScanResult.created_at.desc()).limit(5).all()
            recent_scans_list = [
                {
                    'id': scan.id,
                    'scan_type': scan.scan_type,
                    'severity': scan.severity,
                    'created_at': scan.created_at.isoformat(),
                    'details': scan.details
                } for scan in recent_scans
            ]
            logging.debug(f"Recent scans retrieved: {len(recent_scans_list)} scans, RequestID: {request_id}")
        except DatabaseError as e:
            logging.error(f"Error querying recent scans: {e}, RequestID: {request_id}")
            db.session.rollback()
            recent_scans_list = []

        # Login Logs
        try:
            login_logs = [
                {'time': (now - timedelta(hours=i)).isoformat(), 
                 'ip': f'192.168.1.{i+1}', 
                 'status': 'Success' if i % 2 == 0 else 'Failed'}
                for i in range(5)
            ]
        except Exception as e:
            logging.error(f"Error generating login logs: {e}, RequestID: {request_id}")
            login_logs = []

        # Security Tips
        security_tips = [
            'Use strong, unique passwords for each account.',
            'Enable two-factor authentication (2FA) wherever possible.',
            'Regularly update your software to patch vulnerabilities.',
            'Be cautious of phishing emails and suspicious links.',
            'Use a reputable antivirus and keep it updated.'
        ]

        # Notifications
        try:
            notifications = [
                {
                    'title': alert.title,
                    'message': alert.message,
                    'timestamp': alert.created_at.isoformat()
                } for alert in SecurityAlert.query.filter_by(user_id=user_id)
                    .order_by(SecurityAlert.created_at.desc()).limit(3).all()
            ]
        except DatabaseError as e:
            logging.error(f"Error querying notifications: {e}, RequestID: {request_id}")
            notifications = []

        # Network Activity
        network_activity = get_network_activity()

        data = {
            'system': system_stats,
            'security': {
                'active_threats': {
                    'today': get_active_threats(1),
                    'week': get_active_threats(7),
                    'month': get_active_threats(30)
                },
                'severity': severity_counts,
                'recent_alerts': len(recent_alerts_list),
                'risk_score': risk_score
            },
            'recent_scans': recent_scans_list,
            'recent_threats': recent_threats_list,
            'threat_timeline': threat_timeline,
            'threat_types': threat_types,
            'risk_score_breakdown': risk_score_breakdown,
            'notifications': notifications,
            'access_requests': access_requests_list,
            'security_tips': security_tips,
            'recent_alerts': recent_alerts_list,
            'login_log': login_logs,
            'threat_trend': threat_trend,
            'security_metrics': security_metrics,
            'network_activity': network_activity,
            'request_id': request_id
        }

        logging.debug(f"Dashboard data prepared for user {user_id}, RequestID: {request_id}")
        try:
            return jsonify(data), 200  # Simplified JSON serialization
        except Exception as e:
            logging.error(f"JSON serialization error: {str(e)}, RequestID: {request_id}")
            return jsonify({'error': f'Failed to serialize dashboard data: {str(e)}', 'request_id': request_id}), 500

    except Exception as e:
        logging.error(f"Error fetching dashboard data: {str(e)}, RequestID: {request_id}")
        db.session.rollback()
        return jsonify({'error': f'Failed to fetch dashboard data: {str(e)}', 'request_id': request_id}), 500

@user_dashboard_bp.route('/api/access-request/<request_id>/allow', methods=['POST'])
@login_required
def allow_access_request(request_id):
    """Allow an access request."""
    request_id_str = str(request_id)
    try:
        access_request = AccessRequest.query.filter_by(id=request_id_str, user_id=str(current_user.id)).first()
        if not access_request:
            logging.error(f"Access request {request_id_str} not found for user {current_user.id}, RequestID: {request_id}")
            return jsonify({'error': 'Access request not found', 'request_id': request_id}), 404
        access_request.status = 'Allowed'
        db.session.commit()
        logging.info(f"Access request {request_id_str} allowed by user {current_user.id}, RequestID: {request_id}")
        return jsonify({'message': 'Access request allowed', 'request_id': request_id}), 200
    except DatabaseError as e:
        db.session.rollback()
        logging.error(f"Error allowing access request {request_id_str}: {e}, RequestID: {request_id}")
        return jsonify({'error': f'Failed to allow access request: {str(e)}', 'request_id': request_id}), 500

@user_dashboard_bp.route('/api/access-request/<request_id>/deny', methods=['POST'])
@login_required
def deny_access_request(request_id):
    """Deny an access request."""
    request_id_str = str(request_id)
    try:
        access_request = AccessRequest.query.filter_by(id=request_id_str, user_id=str(current_user.id)).first()
        if not access_request:
            logging.error(f"Access request {request_id_str} not found for user {current_user.id}, RequestID: {request_id}")
            return jsonify({'error': 'Access request not found', 'request_id': request_id}), 404
        access_request.status = 'Denied'
        db.session.commit()
        logging.info(f"Access request {request_id_str} denied by user {current_user.id}, RequestID: {request_id}")
        return jsonify({'message': 'Access request denied', 'request_id': request_id}), 200
    except DatabaseError as e:
        db.session.rollback()
        logging.error(f"Error denying access request {request_id_str}: {e}, RequestID: {request_id}")
        return jsonify({'error': f'Failed to deny access request: {str(e)}', 'request_id': request_id}), 500