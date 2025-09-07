from flask import Blueprint, render_template, jsonify
from datetime import datetime, timedelta
from models import DeviceActivityLog
from extensions import db
from flask_login import login_required, current_user
from sqlalchemy import func
from user_dashboard import get_system_stats

data_dashboard_bp = Blueprint('data_dashboard', __name__)


@data_dashboard_bp.route('/data-dashboard')
@login_required
def data_dashboard():
    return render_template('data-dashboard.html')


# 📊 Device statistics
@data_dashboard_bp.route('/api/device-stats')
@login_required
def get_device_stats():
    try:
        system_stats = get_system_stats()

        total_devices = db.session.query(DeviceActivityLog.device_id).distinct().count()
        active_devices = DeviceActivityLog.query.filter_by(status='Active').count()
        vulnerable_devices = DeviceActivityLog.query.filter(
            (DeviceActivityLog.threat_detected.isnot(None)) |
            (DeviceActivityLog.anomaly_score > 0.7)
        ).count()
        total_scans = DeviceActivityLog.query.count()

        last_scan_entry = DeviceActivityLog.query.order_by(DeviceActivityLog.timestamp.desc()).first()
        last_scan = last_scan_entry.timestamp.strftime('%Y-%m-%d') if last_scan_entry else None

        most_common_type = (
            db.session.query(DeviceActivityLog.protocol, func.count(DeviceActivityLog.protocol))
            .group_by(DeviceActivityLog.protocol)
            .order_by(func.count(DeviceActivityLog.protocol).desc())
            .first()
        )
        most_common_type = most_common_type[0] if most_common_type else "Unknown"

        return jsonify({
            'total_devices': total_devices,
            'active_devices': active_devices,
            'vulnerable_devices': vulnerable_devices,
            'total_scans': total_scans,
            'last_scan': last_scan,
            'most_common_type': most_common_type,
            'system_stats': system_stats
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 📈 Threat trends by date & severity
@data_dashboard_bp.route('/api/threat-trends')
@login_required
def get_threat_trends():
    logs = DeviceActivityLog.query.filter(DeviceActivityLog.threat_detected.isnot(None)).all()

    trends = {}
    for log in logs:
        date = log.timestamp.date().isoformat()
        severity = "High" if log.anomaly_score and log.anomaly_score > 0.8 else "Low"
        trends.setdefault(date, {"High": 0, "Medium": 0, "Low": 0})
        trends[date][severity] += 1

    return jsonify({
        'dates': list(trends.keys()),
        'high': [val["High"] for val in trends.values()],
        'medium': [val["Medium"] for val in trends.values()],
        'low': [val["Low"] for val in trends.values()]
    })


# 🛡 Vulnerability distribution
@data_dashboard_bp.route('/api/vulnerability-distribution')
@login_required
def get_vulnerability_distribution():
    distribution = {
        "High": DeviceActivityLog.query.filter(DeviceActivityLog.anomaly_score >= 0.8).count(),
        "Medium": DeviceActivityLog.query.filter(
            (DeviceActivityLog.anomaly_score >= 0.5) & (DeviceActivityLog.anomaly_score < 0.8)
        ).count(),
        "Low": DeviceActivityLog.query.filter(DeviceActivityLog.anomaly_score < 0.5).count(),
    }
    return jsonify(distribution)


# 🚨 Recent threats
@data_dashboard_bp.route('/api/recent-threats')
@login_required
def get_recent_threats():
    recent = DeviceActivityLog.query.filter(DeviceActivityLog.threat_detected.isnot(None)) \
        .order_by(DeviceActivityLog.timestamp.desc()) \
        .limit(10).all()
    return jsonify([log.to_dict() for log in recent])


# 📡 Device protocol distribution (instead of "Device_Type")
@data_dashboard_bp.route('/api/device-types')
@login_required
def get_device_types():
    type_distribution = (
        db.session.query(DeviceActivityLog.protocol, func.count(DeviceActivityLog.protocol))
        .group_by(DeviceActivityLog.protocol)
        .all()
    )
    return jsonify({proto or "Unknown": count for proto, count in type_distribution})


# 🔐 Security score (simple heuristic)
@data_dashboard_bp.route('/api/security-score')
@login_required
def get_security_score():
    total_logs = DeviceActivityLog.query.count()
    if total_logs == 0:
        return jsonify({
            'overall_score': 100,
            'vulnerability_score': 100,
            'threat_score': 100
        })

    high_vulns = DeviceActivityLog.query.filter(DeviceActivityLog.anomaly_score >= 0.8).count()
    high_threats = DeviceActivityLog.query.filter(DeviceActivityLog.threat_detected.isnot(None)).count()

    vulnerability_score = 100 - (high_vulns / total_logs * 100)
    threat_score = 100 - (high_threats / total_logs * 100)
    overall_score = (vulnerability_score + threat_score) / 2

    return jsonify({
        'overall_score': round(overall_score, 2),
        'vulnerability_score': round(vulnerability_score, 2),
        'threat_score': round(threat_score, 2)
    })
