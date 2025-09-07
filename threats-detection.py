import tensorflow as tf
from datetime import datetime
from models import Threat
from extensions import db

class ThreatDetectionModel:
    def __init__(self):
        self.model = None
        self.load_model()
    
    def load_model(self):
        # Load your trained model
        model_path = 'ml_models/threats-detection/1'
        self.model = tf.keras.models.load_model(model_path)
    
    def predict(self, data):
        # Implement threat prediction logic
        prediction = self.model.predict(data)
        return self.process_prediction(prediction)
    
    def process_prediction(self, prediction):
        # Process model output and return threat assessment
        return {
            'threat_level': 'high' if prediction > 0.8 else 'medium' if prediction > 0.5 else 'low',
            'confidence': float(prediction),
            'timestamp': datetime.utcnow().isoformat()
        }
import random
import uuid
import datetime
import time
import threading

class ThreatDetector:
    def __init__(self, devices=None, threats=None, alerts=None):
        self.devices = devices or []
        self.threats = threats or []
        self.alerts = alerts or []
        self.running = False
        self.thread = None
        
        # Threat patterns for simulation
        self.threat_patterns = {
            'Malware': {
                'indicators': ['Unusual process activity', 'Unexpected file changes', 'Network anomalies'],
                'severity_distribution': {'Low': 0.2, 'Medium': 0.3, 'High': 0.3, 'Critical': 0.2},
                'mitigation': 'Isolate affected system and run full antivirus scan'
            },
            'Phishing': {
                'indicators': ['Suspicious email links', 'Domain spoofing', 'Credential theft attempts'],
                'severity_distribution': {'Low': 0.3, 'Medium': 0.4, 'High': 0.2, 'Critical': 0.1},
                'mitigation': 'Block sender, report to security team, and reset affected credentials'
            },
            'DDoS': {
                'indicators': ['Traffic spike', 'Service degradation', 'Bandwidth saturation'],
                'severity_distribution': {'Low': 0.1, 'Medium': 0.2, 'High': 0.4, 'Critical': 0.3},
                'mitigation': 'Enable traffic filtering and contact ISP for assistance'
            },
            'Brute Force': {
                'indicators': ['Multiple failed login attempts', 'Account lockouts', 'Authentication anomalies'],
                'severity_distribution': {'Low': 0.2, 'Medium': 0.3, 'High': 0.3, 'Critical': 0.2},
                'mitigation': 'Temporarily block source IP and enforce password policy'
            },
            'SQL Injection': {
                'indicators': ['Malformed database queries', 'Unexpected database errors', 'Data exfiltration'],
                'severity_distribution': {'Low': 0.1, 'Medium': 0.2, 'High': 0.4, 'Critical': 0.3},
                'mitigation': 'Patch vulnerable application and audit affected data'
            }
        }
    
    def start_monitoring(self):
        """Start the threat detection monitoring in a separate thread"""
        if self.running:
            return False
        
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_loop)
        self.thread.daemon = True
        self.thread.start()
        return True
    
    def stop_monitoring(self):
        """Stop the threat detection monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs in a separate thread"""
        while self.running:
            # Simulate AI detection by randomly generating threats
            if random.random() < 0.3:  # 30% chance of detecting a threat each cycle
                self._detect_threat()
            
            # Update device risk scores
            self._update_device_risks()
            
            # Sleep for a random interval to simulate real-time monitoring
            time.sleep(random.uniform(5, 15))
    
    def _detect_threat(self):
        """Simulate detecting a new threat"""
        if not self.devices:
            return
        
        # Select a random device and threat type
        affected_device = random.choice(self.devices)
        threat_type = random.choice(list(self.threat_patterns.keys()))
        pattern = self.threat_patterns[threat_type]
        
        # Determine severity based on the threat type's distribution
        severity_items = list(pattern['severity_distribution'].items())
        severity = random.choices(
            [s[0] for s in severity_items],
            weights=[s[1] for s in severity_items],
            k=1
        )[0]
        
        # Create a new threat
        threat_id = str(uuid.uuid4())
        indicator = random.choice(pattern['indicators'])
        
        new_threat = {
            'id': threat_id,
            'name': f'{threat_type}: {indicator}',
            'type': threat_type,
            'description': f'AI detected {indicator.lower()} on {affected_device["name"]}',
            'severity': severity,
            'detected_at': datetime.datetime.now().isoformat(),
            'status': 'Active',
            'affected_device': affected_device['id'],
            'indicator': indicator,
            'recommended_action': pattern['mitigation']
        }
        
        # Add to threats list
        self.threats.append(new_threat)
        
        # Create an alert
        alert_id = str(uuid.uuid4())
        new_alert = {
            'id': alert_id,
            'threat_id': threat_id,
            'title': f'New {severity} {threat_type} Threat Detected',
            'message': f'{indicator} detected on {affected_device["name"]}',
            'created_at': datetime.datetime.now().isoformat(),
            'read': False
        }
        
        # Add to alerts list
        self.alerts.append(new_alert)
        
        # Update device risk score
        self._update_device_risk(affected_device, severity)
    
    def _update_device_risks(self):
        """Update risk scores for all devices"""
        for device in self.devices:
            # Gradually decrease risk score over time (simulating recovery)
            if device['risk_score'] > 0:
                device['risk_score'] = max(0, device['risk_score'] - random.randint(1, 5))
    
    def _update_device_risk(self, device, severity):
        """Update risk score for a specific device based on a new threat"""
        severity_scores = {
            'Low': random.randint(5, 15),
            'Medium': random.randint(15, 40),
            'High': random.randint(40, 70),
            'Critical': random.randint(70, 100)
        }
        
        # Increase risk score based on severity
        device['risk_score'] = min(100, device['risk_score'] + severity_scores[severity])
        
        # Update device status if risk is very high
        if device['risk_score'] > 80:
            device['status'] = 'at-risk'


    def analyze_device_behavior(self, device_data):
        """Analyze device behavior for potential threats"""
        anomaly_score = 0
        threat_indicators = []
        
        # Check CPU usage spikes
        if device_data['metrics']['cpu_usage'] > 90:
            anomaly_score += 0.3
            threat_indicators.append('High CPU usage detected')
        
        # Check memory usage
        if device_data['metrics']['memory_usage'] > 85:
            anomaly_score += 0.2
            threat_indicators.append('High memory consumption')
        
        # Check network anomalies
        network = device_data['metrics']['network_io']
        if network['bytes_sent'] > 1000000000:  # 1GB
            anomaly_score += 0.25
            threat_indicators.append('Unusual network activity')
        
        # Generate threat if anomaly score is high
        if anomaly_score > 0.5:
            self._generate_threat(device_data['device_id'], threat_indicators)
    
    def _generate_threat(self, device_id, indicators):
        """Generate a new threat based on detected anomalies"""
        threat = Threat(
            name=f"Behavioral Anomaly: {', '.join(indicators)}",
            type='Anomaly Detection',
            description=f"AI detected unusual behavior: {', '.join(indicators)}",
            severity='High' if len(indicators) > 2 else 'Medium',
            affected_device=device_id,
            indicator=indicators[0],
            recommended_action='Investigate system behavior and check for unauthorized activities'
        )
        
        db.session.add(threat)
        db.session.commit()
        
        # Create alert for the threat
        alert = Alert(
            threat_id=threat.id,
            title=f"New {threat.severity} Security Anomaly Detected",
            message=f"Multiple security anomalies detected on device {device_id}",
            created_at=datetime.utcnow()
        )
        
        db.session.add(alert)
        db.session.commit()


class ThreatResponse:
    def __init__(self):
        self.response_actions = {
            'Malware': self._handle_malware,
            'Phishing': self._handle_phishing,
            'DDoS': self._handle_ddos,
            'Brute Force': self._handle_brute_force,
            'SQL Injection': self._handle_sql_injection
        }
    
    def handle_threat(self, threat):
        if threat['type'] in self.response_actions:
            return self.response_actions[threat['type']](threat)
        return self._handle_unknown(threat)
    
    def _handle_malware(self, threat):
        return {
            'action': 'isolate',
            'command': 'quarantine_device',
            'params': {'device_id': threat['affected_device']}
        }

    def _handle_ddos(self, threat):
        return {
            'action': 'mitigate',
            'command': 'enable_traffic_filtering',
            'params': {'device_id': threat['affected_device']}
        }