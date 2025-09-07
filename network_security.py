from flask import Blueprint, jsonify, request
from models import NetworkDevice, NetworkMetric, SecurityAudit
from extensions import db
from datetime import datetime, timedelta

network_bp = Blueprint('network', __name__)

@network_bp.route('/api/network/performance/metrics', methods=['GET'])
def get_network_metrics():
    try:
        # Get time range
        time_range = request.args.get('range', '1h')
        end_date = datetime.now()
        
        if time_range == '1h':
            start_date = end_date - timedelta(hours=1)
        elif time_range == '24h':
            start_date = end_date - timedelta(days=1)
        elif time_range == '7d':
            start_date = end_date - timedelta(days=7)
        else:
            start_date = end_date - timedelta(hours=1)

        # Get network metrics
        metrics = NetworkMetric.query.filter(
            NetworkMetric.timestamp.between(start_date, end_date)
        ).all()

        # Calculate performance metrics
        performance_data = {
            'bandwidth_usage': [],
            'latency': [],
            'packet_loss': [],
            'error_rate': []
        }

        for metric in metrics:
            timestamp = metric.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            performance_data['bandwidth_usage'].append({
                'timestamp': timestamp,
                'value': metric.bandwidth_usage
            })
            performance_data['latency'].append({
                'timestamp': timestamp,
                'value': metric.latency
            })
            performance_data['packet_loss'].append({
                'timestamp': timestamp,
                'value': metric.packet_loss
            })
            performance_data['error_rate'].append({
                'timestamp': timestamp,
                'value': metric.error_rate
            })

        return jsonify({
            'status': 'success',
            'data': {
                'performance_metrics': performance_data,
                'summary': {
                    'avg_bandwidth_usage': sum(m.bandwidth_usage for m in metrics) / len(metrics) if metrics else 0,
                    'avg_latency': sum(m.latency for m in metrics) / len(metrics) if metrics else 0,
                    'avg_packet_loss': sum(m.packet_loss for m in metrics) / len(metrics) if metrics else 0,
                    'avg_error_rate': sum(m.error_rate for m in metrics) / len(metrics) if metrics else 0
                },
                'time_range': {
                    'start': start_date.strftime('%Y-%m-%d %H:%M:%S'),
                    'end': end_date.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/api/network/security/audit', methods=['POST'])
def perform_security_audit():
    try:
        data = request.get_json()
        device_ids = data.get('device_ids', [])
        audit_type = data.get('type', 'full')

        # Get devices to audit
        devices = NetworkDevice.query.filter(NetworkDevice.id.in_(device_ids)).all() if device_ids else NetworkDevice.query.all()

        audit_results = []
        for device in devices:
            # Perform security checks
            security_score = calculate_security_score(device)
            vulnerabilities = identify_vulnerabilities(device)
            compliance_status = check_compliance(device)

            # Create audit record
            audit = SecurityAudit(
                device_id=device.id,
                type=audit_type,
                security_score=security_score,
                timestamp=datetime.now()
            )
            db.session.add(audit)

            audit_results.append({
                'device_id': device.id,
                'device_name': device.name,
                'security_score': security_score,
                'vulnerabilities': vulnerabilities,
                'compliance_status': compliance_status,
                'recommendations': generate_security_recommendations(device, vulnerabilities)
            })

        db.session.commit()

        return jsonify({
            'status': 'success',
            'data': {
                'audit_results': audit_results,
                'summary': {
                    'total_devices': len(devices),
                    'average_security_score': sum(r['security_score'] for r in audit_results) / len(audit_results) if audit_results else 0,
                    'compliant_devices': sum(1 for r in audit_results if r['compliance_status']['is_compliant']),
                    'vulnerable_devices': sum(1 for r in audit_results if r['vulnerabilities'])
                }
            }
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def calculate_security_score(device):
    base_score = 10  # Start with perfect score
    
    # Check firmware version
    if device.firmware_version != device.latest_firmware_version:
        base_score -= 2
    
    # Check security features
    if not device.encryption_enabled:
        base_score -= 2
    if not device.firewall_enabled:
        base_score -= 2
    
    # Check recent security incidents
    recent_incidents = SecurityIncident.query.filter_by(
        device_id=device.id
    ).filter(
        SecurityIncident.timestamp >= datetime.now() - timedelta(days=30)
    ).count()
    
    base_score -= min(recent_incidents, 4)  # Deduct up to 4 points for recent incidents
    
    return max(base_score, 0)  # Ensure score doesn't go below 0

def identify_vulnerabilities(device):
    vulnerabilities = []
    
    # Check for common vulnerabilities
    if not device.encryption_enabled:
        vulnerabilities.append({
            'type': 'encryption',
            'severity': 'high',
            'description': 'Device encryption is not enabled'
        })
    
    if not device.firewall_enabled:
        vulnerabilities.append({
            'type': 'firewall',
            'severity': 'high',
            'description': 'Device firewall is not enabled'
        })
    
    if device.firmware_version != device.latest_firmware_version:
        vulnerabilities.append({
            'type': 'firmware',
            'severity': 'medium',
            'description': 'Device firmware is not up to date'
        })
    
    return vulnerabilities

def check_compliance(device):
    compliance_checks = {
        'encryption': device.encryption_enabled,
        'firewall': device.firewall_enabled,
        'firmware': device.firmware_version == device.latest_firmware_version,
        'password_policy': device.password_meets_policy
    }
    
    is_compliant = all(compliance_checks.values())
    
    return {
        'is_compliant': is_compliant,
        'checks': compliance_checks
    }

def generate_security_recommendations(device, vulnerabilities):
    recommendations = []
    
    for vuln in vulnerabilities:
        if vuln['type'] == 'encryption':
            recommendations.append('Enable device encryption immediately')
        elif vuln['type'] == 'firewall':
            recommendations.append('Enable and configure device firewall')
        elif vuln['type'] == 'firmware':
            recommendations.append('Update device firmware to latest version')
    
    return recommendations