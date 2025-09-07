import json
import os
import datetime
import logging
from uuid import uuid4
from flask import Blueprint, jsonify, request, render_template, make_response
from flask_cors import cross_origin
from flask_login import login_required, current_user
import numpy as np
from models import SecurityScanResult, Threat, ThreatDetails, Alert
from extensions import db, limiter
import joblib
from tensorflow.keras.models import load_model
from system_metrics import (
    get_cpu_usage, get_memory_usage, get_disk_usage, get_network_stats
)
from security_alerts import create_alert

# ---------------- Logging Configuration ----------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s - RequestID: %(request_id)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z'
)
logging.getLogger().addFilter(lambda record: setattr(record, 'request_id', str(uuid4())) or True)

# ---------------- Flask Blueprint ----------------
security_scan_bp = Blueprint('security_scan', __name__)

# ---------------- Constants ----------------
VALID_INPUT_TYPES = {'device', 'threat'}
VALID_SEVERITIES = {'Low', 'Medium', 'High', 'Critical'}
VALID_PROTOCOLS = {'SSH', 'RDP', 'HTTPS', 'Telnet', 'HTTP', 'FTP', 'DNS', 'SMTP', 'SMB', None}
MAX_FEATURES_LENGTH = 100
DEMO_MODE = os.environ.get("DEMO_MODE") == "true"

# ---------------- Load threat signatures ----------------
THREAT_SIGNATURES = []
try:
    with open("data/threats.json", "r") as f:
        THREAT_SIGNATURES = json.load(f).get('threats', [])
    logging.info(f"Loaded {len(THREAT_SIGNATURES)} threat signatures")
except FileNotFoundError:
    logging.warning("threats.json not found: continuing without JSON threat signatures")
    THREAT_SIGNATURES = []
except Exception as e:
    logging.error(f"Failed to load threats.json: {e}")
    THREAT_SIGNATURES = []

# ---------------- ML Manager ----------------
class MLManager:
    def __init__(self, device_model_path, device_scaler_path, threat_model_path, threat_scaler_path):
        try:
            for path in [device_model_path, device_scaler_path, threat_model_path, threat_scaler_path]:
                if not os.path.exists(path):
                    raise FileNotFoundError(f"File not found: {path}")

            self.device_model = load_model(device_model_path)
            self.threat_model = load_model(threat_model_path)
            with open(device_scaler_path, 'rb') as f:
                self.device_scaler = joblib.load(f)
            with open(threat_scaler_path, 'rb') as f:
                self.threat_scaler = joblib.load(f)

            self.device_input_shape = self.device_model.input_shape[1]
            self.threat_input_shape = self.threat_model.input_shape[1]
            logging.info(
                f"MLManager initialized: device_input_shape={self.device_input_shape}, "
                f"threat_input_shape={self.threat_input_shape}"
            )
        except Exception as e:
            logging.error(f"MLManager init error: {e}")
            raise

    def preprocess_features(self, features, expected_len):
        if isinstance(features, str):
            try:
                features = json.loads(features)
            except Exception as e:
                raise ValueError(f"Features string is not valid JSON: {e}")

        if not isinstance(features, list) or len(features) > MAX_FEATURES_LENGTH:
            raise ValueError(f"Features must be a list with at most {MAX_FEATURES_LENGTH} elements")
        if not all(isinstance(x, (int, float)) for x in features):
            raise ValueError("Features must contain only numbers")

        if len(features) < expected_len:
            features += [0.0] * (expected_len - len(features))
        elif len(features) > expected_len:
            features = features[:expected_len]
        return np.array(features).reshape(1, -1)

    def analyze_device(self, data):
        features = self.preprocess_features(data['features'], self.device_input_shape)
        scaled = self.device_scaler.transform(features)
        prediction = float(self.device_model.predict(scaled, verbose=0)[0][0])
        ip_address = data.get('ip_address', 'N/A')
        port = data.get('port', 'N/A')
        protocol = data.get('protocol', 'N/A')
        return {
            'type': 'Device Scan',
            'threat_detected': prediction > 0.5,
            'severity': 'High' if prediction > 0.9 else 'Medium' if prediction > 0.7 else 'Low',
            'description': f"Device anomaly detected with confidence {prediction:.2f}",
            'confidence': prediction,
            'name': f"Device Anomaly {ip_address or 'Unknown'}",
            'indicator': f"IP: {ip_address}, Port: {port}, Protocol: {protocol}"
        }

    def analyze_threat(self, data):
        features = self.preprocess_features(data['features'], self.threat_input_shape)
        scaled = self.threat_scaler.transform(features)
        prediction = float(self.threat_model.predict(scaled, verbose=0)[0][0])
        ip_address = data.get('ip_address', 'N/A')
        port = data.get('port', 'N/A')
        protocol = data.get('protocol', 'N/A')
        return {
            'type': 'Threat Scan',
            'threat_detected': prediction > 0.5,
            'severity': 'High' if prediction > 0.9 else 'Medium' if prediction > 0.7 else 'Low',
            'description': f"Threat detected with confidence {prediction:.2f}",
            'confidence': prediction,
            'name': f"Threat Signature {ip_address or 'Unknown'}",
            'indicator': f"IP: {ip_address}, Port: {port}, Protocol: {protocol}"
        }

    def generate_recommendations(self, result, json_detections):
        if not result.get('threat_detected', False) and not json_detections:
            return ["System appears safe. No immediate action needed."]

        recs = ["Run a full system malware scan.", "Isolate affected device from network."]

        if result.get('severity') == 'High' or any(d['severity'] == 'High' for d in json_detections):
            recs.append("Initiate incident response protocol.")
        elif result.get('severity') == 'Medium' or any(d['severity'] == 'Medium' for d in json_detections):
            recs.append("Monitor system activity closely.")

        if any(d.get('protocol') in {'SSH', 'RDP', 'Telnet'} for d in json_detections):
            recs.append("Disable unused remote access protocols (SSH, RDP, Telnet).")
        if any(d.get('activity') in {'SQL Injection', 'XSS Attack Vector'} for d in json_detections):
            recs.append("Implement Web Application Firewall (WAF) rules.")
        if any(d.get('activity') == 'Malware Beaconing' for d in json_detections):
            recs.append("Block suspicious IP addresses and domains.")

        return recs

# ---------------- Initialize ML Manager ----------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # project root

ml_manager = None
try:
    ml_manager = MLManager(
        device_model_path=os.path.join(BASE_DIR, 'ml_models', 'device_model.h5'),
        device_scaler_path=os.path.join(BASE_DIR, 'ml_models', 'scaler_device.pkl'),
        threat_model_path=os.path.join(BASE_DIR, 'ml_models', 'threat_model.h5'),
        threat_scaler_path=os.path.join(BASE_DIR, 'ml_models', 'scaler_threat.pkl')
    )
    logging.info("MLManager successfully initialized")
except Exception as e:
    logging.critical(f"MLManager failed to initialize: {e}")
    ml_manager = None

# ---------------- Validation Functions ----------------
def validate_ip_address(ip_address):
    if not ip_address:
        return True
    try:
        parts = ip_address.split('.')
        if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
            return False
        return True
    except (ValueError, AttributeError):
        return False

def validate_port(port):
    if port is None:
        return True
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

# ---------------- Check JSON Threats ----------------
def check_json_threats(ip_address=None, port=None, protocol=None):
    detections = []
    if not THREAT_SIGNATURES:
        return detections
    try:
        for sig in THREAT_SIGNATURES:
            if sig.get("Threat Detected", "").lower() != "yes":
                continue
            sig_protocol = sig.get("Protocol", "").upper()
            input_protocol = protocol.upper() if protocol else None
            if (ip_address and sig.get("IP Address") != ip_address) or \
               (port is not None and sig.get("Port") != port) or \
               (input_protocol and sig_protocol != input_protocol):
                continue

            anomaly_score = float(sig.get("Anomaly Score", 0))
            severity = (
                "Critical" if anomaly_score >= 0.95 else
                "High" if anomaly_score >= 0.9 else
                "Medium" if anomaly_score >= 0.85 else
                "Low"
            )
            detections.append({
                "timestamp": sig.get("Timestamp", datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                "ip_address": sig.get("IP Address"),
                "port": sig.get("Port"),
                "protocol": sig.get("Protocol"),
                "activity": sig.get("Activity", "Unknown"),
                "severity": severity,
                "details": f"Detected activity: {sig.get('Activity', 'Unknown')} with anomaly score {anomaly_score}",
                "name": sig.get("Activity", "Unknown Threat"),
                "threat_detected": True   # ✅ always include flag
            })

        if DEMO_MODE:
            logging.info("DEMO_MODE enabled: returning all threat signatures")
            return detections or THREAT_SIGNATURES
        return detections
    except Exception as e:
        logging.error(f"Error in check_json_threats: {e}")
        return []

# ---------------- Run Security Scan ----------------
def run_security_scan(data, user_id=None):
    if not ml_manager:
        raise RuntimeError("ML model not initialized")

    input_type = data.get("input_type")
    ip_address = data.get("ip_address")
    port = data.get("port")
    protocol = data.get("protocol")
    device_id = data.get("device_id")

    if input_type not in VALID_INPUT_TYPES:
        raise ValueError(f"Invalid input_type. Must be one of {VALID_INPUT_TYPES}")

    if not isinstance(data.get("features"), (list, str)):
        raise ValueError("Features must be a list or JSON string of numbers")

    if not validate_ip_address(ip_address):
        raise ValueError("Invalid IP address format")
    if not validate_port(port):
        raise ValueError("Invalid port number")
    if protocol not in VALID_PROTOCOLS:
        raise ValueError(f"Invalid protocol. Must be one of {VALID_PROTOCOLS}")

    result = ml_manager.analyze_device(data) if input_type == 'device' else ml_manager.analyze_threat(data)
    result.setdefault("threat_detected", False)   # ✅ enforce flag always exists

    json_detections = check_json_threats(ip_address, port, protocol)
    recommendations = ml_manager.generate_recommendations(result, json_detections)

    return {
        "ml_result": result,
        "recommendations": recommendations,
        "json_detections": json_detections,
        "user_id": user_id,
        "device_id": device_id
    }

# ---------------- Solve Scan Function ----------------
def solve_scan(scan_result):
    try:
        if not scan_result.get('ml_result', {}).get('threat_detected', False) and not scan_result.get('json_detections'):
            logging.info("No threats detected")
            return ["No threats detected. System safe."]

        ml_res = scan_result.get('ml_result', {})
        json_detections = scan_result.get('json_detections', [])
        actions_taken = []

        # Block ML-detected threats
        ip = ml_res.get('indicator', '').split('IP: ')[-1].split(',')[0]
        if ip and ip != 'N/A':
            actions_taken.append(f"Blocked IP {ip} at firewall")

        device_id = scan_result.get('device_id')
        if device_id:
            actions_taken.append(f"Isolated device {device_id} from network")

        protocol = ml_res.get('indicator', '').split('Protocol: ')[-1]
        if protocol and protocol != 'N/A':
            actions_taken.append(f"Disabled protocol {protocol} temporarily")

        # Block JSON-detected threats
        for det in json_detections:
            if det.get('ip_address'):
                actions_taken.append(f"Blocked IP {det['ip_address']}")
            if det.get('port'):
                actions_taken.append(f"Closed port {det['port']}")

        logging.info(f"Threat mitigation actions: {actions_taken}")
        return actions_taken
    except Exception as e:
        logging.error(f"Error in solve_scan: {e}")
        return [f"Failed to automatically handle threats: {e}"]

# ---------------- Health Check ----------------
@security_scan_bp.route('/api/health', methods=['GET'])
@cross_origin(supports_credentials=True)
def health_check():
    try:
        system_status = {
            'cpu_usage': get_cpu_usage(interval=0.5),
            'memory_usage': get_memory_usage(),
            'disk_usage': get_disk_usage(),
            'network_stats': get_network_stats()
        }
        status = {
            'ml_manager_initialized': ml_manager is not None,
            'threat_signatures_loaded': len(THREAT_SIGNATURES) > 0,
            'database_accessible': db.session.execute('SELECT 1').scalar() is not None,
            'current_user_authenticated': current_user.is_authenticated,
            'system_metrics': system_status
        }
        logging.info(f"Health check: {status}")
        return jsonify(status), 200
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        return jsonify({'error': f'Health check failed: {str(e)}'}), 500

# ---------------- Security Scan Page ----------------
@security_scan_bp.route('/scan')
@login_required
def security_scan_page():
    try:
        user_id = str(current_user.id) if current_user.is_authenticated else 'anonymous'
        logging.debug(f"Rendering security scan page for user: {user_id}, is_authenticated: {current_user.is_authenticated}")
        return render_template('security-scan.html')
    except Exception as e:
        logging.error(f"Error rendering security scan page: {e}")
        return jsonify({'error': 'Failed to load scan page'}), 500

# ---------------- Security Scan API ----------------
# ---------------- Security Scan API (Insert into ThreatDetails + Threat) ----------------
@security_scan_bp.route('/api/security-scan', methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def security_scan():
    request_id = str(uuid4())
    logging.debug(f"Security scan API called, user_id: {current_user.id}")
    try:
        data = request.get_json(force=True)
        if isinstance(data, str):
            data = json.loads(data)

        device_id = data.get("device_id")
        ip_address = data.get("ip_address")
        port = data.get("port")
        protocol = data.get("protocol")

        # Run the actual security scan
        scan_result = run_security_scan(data, user_id=str(current_user.id))
        logging.debug(f"Scan result: {scan_result}")

        detected_threats = []

        # ---------------- ML result ----------------
        ml_result = scan_result.get("ml_result", {})
        if ml_result.get("threat_detected", False):
            # ThreatDetails
            threat_detail = ThreatDetails(
                name=ml_result.get("name", "AutoDetected Threat"),
                description=ml_result.get("description", "Detected from ML model"),
                severity=ml_result.get("severity", "Low"),
                device_id=device_id,
                model_id=ml_result.get("model_id"),
                ip_address=ip_address or None,
                port=port or None,
                protocol=protocol or None,
                status="detected"
            )
            db.session.add(threat_detail)
            db.session.flush()

            alert = Alert(
                threat_id=threat_detail.id,
                user_id=str(current_user.id),
                title=f"Threat Detected: {threat_detail.name}",
                message=f"A threat '{threat_detail.name}' was detected on device {device_id or 'Unknown'}.",
                severity=threat_detail.severity,
                category="Detection"
            )
            db.session.add(alert)

            # Also insert into Threat table
            recommended_actions = ", ".join(ml_manager.generate_recommendations(ml_result, []))
            threat = Threat(
                name=ml_result.get("name", "AutoDetected Threat"),
                type=ml_result.get("type", "ML Detected"),
                description=ml_result.get("description", "Detected by ML model"),
                severity=ml_result.get("severity", "Low"),
                affected_device=device_id,
                indicator=ml_result.get("indicator"),
                recommended_action=recommended_actions,
                ip_address=ip_address or None,
                port=port or None,
                protocol=protocol or None,
                status="Active"
            )
            db.session.add(threat)
            detected_threats.append(threat_detail)

        # ---------------- JSON detections ----------------
        for det in scan_result.get("json_detections", []):
            # ThreatDetails
            threat_detail = ThreatDetails(
                name=det.get("name", "AutoDetected Threat"),
                description=det.get("details", "Automatically detected"),
                severity=det.get("severity", "Low"),
                device_id=device_id,
                ip_address=det.get("ip_address"),
                port=det.get("port"),
                protocol=det.get("protocol"),
                status="detected"
            )
            db.session.add(threat_detail)
            db.session.flush()

            alert = Alert(
                threat_id=threat_detail.id,
                user_id=str(current_user.id),
                title=f"Threat Detected: {threat_detail.name}",
                message=f"A threat '{threat_detail.name}' was detected on device {device_id or 'Unknown'}.",
                severity=threat_detail.severity,
                category="Detection"
            )
            db.session.add(alert)

            # Also insert into Threat table
            threat = Threat(
                name=det.get("name", "AutoDetected Threat"),
                type="JSON Detected",
                description=det.get("details", "Detected via signature"),
                severity=det.get("severity", "Low"),
                affected_device=device_id,
                indicator=f"IP: {det.get('ip_address')}, Port: {det.get('port')}, Protocol: {det.get('protocol')}",
                recommended_action=", ".join(ml_manager.generate_recommendations({}, [det])),
                ip_address=det.get("ip_address"),
                port=det.get("port"),
                protocol=det.get("protocol"),
                status="Active"
            )
            db.session.add(threat)
            detected_threats.append(threat_detail)

        db.session.commit()

        return jsonify({
            "message": "Scan completed",
            "scan_result": scan_result,
            "detected_threats": [t.id for t in detected_threats]
        }), 200
    except Exception as e:
        logging.error(f"Security scan failed: {e}")
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
