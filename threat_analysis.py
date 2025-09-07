from flask import Blueprint, jsonify, request
from models import Threat, Device, Alert
from datetime import datetime, timedelta
from extensions import db

threat_analysis = Blueprint('threat_analysis', __name__)

@threat_analysis.route('/api/threats/analysis/trends')
def get_threat_trends():
    try:
        days = request.args.get('days', 30, type=int)
        start_date = datetime.now() - timedelta(days=days)
        
        # Get daily threat counts
        daily_threats = db.session.query(
            db.func.date(Threat.created_at).label('date'),
            db.func.count(Threat.id).label('count')
        ).filter(Threat.created_at >= start_date)\
         .group_by(db.func.date(Threat.created_at))\
         .order_by('date').all()
        
        # Get threat type distribution
        threat_types = db.session.query(
            Threat.type,
            db.func.count(Threat.id).label('count')
        ).filter(Threat.created_at >= start_date)\
         .group_by(Threat.type).all()
        
        return jsonify({
            'daily_trends': [{
                'date': str(day.date),
                'count': day.count
            } for day in daily_threats],
            'type_distribution': dict(threat_types),
            'period': {
                'start': start_date.isoformat(),
                'end': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threat_analysis.route('/api/threats/analysis/impact')
def analyze_threat_impact():
    try:
        # Get high-impact threats
        high_impact_threats = Threat.query.filter_by(
            severity='high',
            status='Active'
        ).order_by(Threat.created_at.desc()).all()
        
        # Calculate impact metrics
        affected_devices = Device.query.filter(
            Device.id.in_([threat.device_id for threat in high_impact_threats])
        ).all()
        
        # Get related alerts
        related_alerts = Alert.query.filter(
            Alert.threat_id.in_([threat.id for threat in high_impact_threats])
        ).order_by(Alert.created_at.desc()).all()
        
        return jsonify({
            'high_impact_threats': [threat.to_dict() for threat in high_impact_threats],
            'affected_devices': [device.to_dict() for device in affected_devices],
            'related_alerts': [alert.to_dict() for alert in related_alerts],
            'impact_metrics': {
                'affected_device_count': len(affected_devices),
                'total_alerts': len(related_alerts),
                'risk_level': calculate_risk_level(high_impact_threats)
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500