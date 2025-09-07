from flask import Blueprint, jsonify, request, render_template, current_app, send_file
from datetime import datetime
from models import ThreatDetails, Device, Alert
from extensions import db
from flask_login import login_required, current_user
import pandas as pd
import io
from security_scan import solve_scan
import logging
from uuid import uuid4

# ---------------- Logging Configuration ----------------
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s - RequestID: %(request_id)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z'
)
logging.getLogger().addFilter(lambda record: setattr(record, 'request_id', str(uuid4())) or True)

# ---------------- Flask Blueprint ----------------
threat_bp = Blueprint("threat", __name__)

# -----------------------------
# Page Route
# -----------------------------
@threat_bp.route("/threat_details")
@login_required
def threat_details_page():
    """Render the threat details web page."""
    request_id = str(uuid4())
    try:
        user_id = str(current_user.id) if current_user.is_authenticated else 'anonymous'
        current_app.logger.debug(f"Rendering threat details page for user: {user_id}, RequestID: {request_id}")
        return render_template("threat-details.html")
    except Exception as e:
        current_app.logger.error(f"Error rendering threat_details_page: {str(e)}, RequestID: {request_id}")
        return jsonify({"error": "Failed to load page", "request_id": request_id}), 500

# -----------------------------
# API: Get ThreatDetails
# -----------------------------
@threat_bp.route("/threats", methods=["GET"], endpoint="get_threats")
@login_required
def get_threats():
    """Fetch ThreatDetails for the current user, including unlinked threats."""
    request_id = str(uuid4())
    try:
        severity = request.args.get("severity")
        device_ids_subq = db.session.query(Device.id).filter(Device.user_id == str(current_user.id))
        
        query = ThreatDetails.query.filter(
            (ThreatDetails.device_id.in_(device_ids_subq)) | (ThreatDetails.device_id.is_(None))
        )

        if severity:
            query = query.filter(ThreatDetails.severity == severity)

        threats = query.order_by(ThreatDetails.detected_at.desc()).all()
        response = {
            "threats": [t.to_dict() for t in threats],
            "request_id": request_id
        }
        current_app.logger.debug(f"Retrieved {len(threats)} threats for user {current_user.id}, RequestID: {request_id}")
        return jsonify(response), 200

    except Exception as e:
        current_app.logger.error(f"get_threats failed for user {current_user.id}: {str(e)}, RequestID: {request_id}")
        return jsonify({"error": str(e), "request_id": request_id}), 500

# -----------------------------
# API: Threat Severity Distribution
# -----------------------------
@threat_bp.route("/threats/severity_distribution", methods=["GET"], endpoint="threat_severity_distribution")
@login_required
def threat_severity_distribution():
    """Return threat severity counts for chart visualization."""
    request_id = str(uuid4())
    try:
        device_ids_subq = db.session.query(Device.id).filter(Device.user_id == str(current_user.id))

        threats = ThreatDetails.query.filter(
            (ThreatDetails.device_id.in_(device_ids_subq)) | (ThreatDetails.device_id.is_(None))
        ).all()

        severity_counts = {"High": 0, "Medium": 0, "Low": 0, "Critical": 0}
        for t in threats:
            if t.severity in severity_counts:
                severity_counts[t.severity] += 1

        response = {
            "severity_counts": severity_counts,
            "request_id": request_id
        }
        current_app.logger.debug(f"Severity distribution retrieved: {severity_counts}, RequestID: {request_id}")
        return jsonify(response), 200

    except Exception as e:
        current_app.logger.error(f"threat_severity_distribution failed: {str(e)}, RequestID: {request_id}")
        return jsonify({"error": str(e), "request_id": request_id}), 500

# -----------------------------
# API: Export ThreatDetails
# -----------------------------
@threat_bp.route("/threats/export", methods=["GET"], endpoint="export_threats")
@login_required
def export_threats():
    """Export ThreatDetails for the current user to CSV."""
    request_id = str(uuid4())
    try:
        severity = request.args.get("severity")
        device_ids_subq = db.session.query(Device.id).filter(Device.user_id == str(current_user.id))

        query = ThreatDetails.query.filter(
            (ThreatDetails.device_id.in_(device_ids_subq)) | (ThreatDetails.device_id.is_(None))
        )

        if severity:
            query = query.filter(ThreatDetails.severity == severity)

        threats = query.order_by(ThreatDetails.detected_at.desc()).all()

        df = pd.DataFrame(
            [
                {
                    "ID": t.id,
                    "Name": t.name,
                    "Device ID": t.device_id or "N/A",
                    "Description": t.description or "N/A",
                    "Severity": t.severity or "N/A",
                    "Detected At": t.detected_at.isoformat() if t.detected_at else "N/A",
                    "Model ID": t.model_id or "N/A",
                    "IP Address": t.ip_address or "N/A",
                    "Port": t.port or "N/A",
                    "Protocol": t.protocol or "N/A",
                    "Status": t.status or "N/A",
                }
                for t in threats
            ]
        )

        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)

        current_app.logger.debug(f"Exported {len(threats)} threats to CSV, RequestID: {request_id}")
        return send_file(
            io.BytesIO(output.getvalue().encode("utf-8")),
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"threat_details_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )

    except Exception as e:
        current_app.logger.error(f"export_threats failed: {str(e)}, RequestID: {request_id}")
        return jsonify({"error": str(e), "request_id": request_id}), 500

# -----------------------------
# API: Solve ThreatDetails
# -----------------------------
@threat_bp.route("/threats/<string:threat_id>/solve", methods=["POST"], endpoint="solve_threat")
@login_required
def solve_threat(threat_id):
    """Resolve a specific threat by ID using the solve_scan function."""
    request_id = str(uuid4())
    try:
        threat = ThreatDetails.query.get_or_404(threat_id)

        # Validate ownership
        if threat.device_id:
            device = Device.query.filter_by(id=threat.device_id, user_id=str(current_user.id)).first()
            if not device:
                current_app.logger.warning(f"Unauthorized access to threat {threat_id} by user {current_user.id}, RequestID: {request_id}")
                return jsonify({"error": "Unauthorized", "request_id": request_id}), 403

        # Prepare scan_result format for solve_scan
        scan_result = {
            "ml_result": {
                "threat_detected": True,
                "indicator": f"IP: {threat.ip_address or 'N/A'}, Port: {threat.port or 'N/A'}, Protocol: {threat.protocol or 'N/A'}",
                "severity": threat.severity or "Low",
                "name": threat.name or "Unknown Threat",
                "description": threat.description or "No description"
            },
            "json_detections": [
                {
                    "ip_address": threat.ip_address,
                    "port": threat.port,
                    "protocol": threat.protocol,
                    "severity": threat.severity or "Low",
                    "name": threat.name or "Unknown Threat",
                    "details": threat.description or "No description"
                }
            ],
            "device_id": threat.device_id
        }

        # Run solve_scan to get mitigation actions
        actions = solve_scan(scan_result)

        # Update threat status
        threat.status = "resolved"
        threat.updated_at = datetime.utcnow()
        db.session.add(threat)

        # Create resolution alert
        alert = Alert(
            threat_id=threat.id,
            user_id=str(current_user.id),
            title=f"Threat Resolved: {threat.name}",
            message=f"The threat '{threat.name}' has been resolved. Actions taken: {', '.join(actions)}",
            severity=threat.severity or "Low",
            category="Resolution",
            created_at=datetime.utcnow()
        )
        db.session.add(alert)

        db.session.commit()

        response = {
            "message": f"Threat {threat_id} resolved",
            "actions_taken": actions,
            "threat": threat.to_dict(),
            "request_id": request_id
        }
        current_app.logger.info(f"Threat {threat_id} resolved for user {current_user.id}: {actions}, RequestID: {request_id}")
        return jsonify(response), 200

    except Exception as e:
        current_app.logger.error(f"solve_threat failed for threat {threat_id}: {str(e)}, RequestID: {request_id}")
        db.session.rollback()
        return jsonify({"error": str(e), "request_id": request_id}), 500

# -----------------------------
# API: ThreatDetails Summary
# -----------------------------
@threat_bp.route("/threats/summary", methods=["GET"], endpoint="get_threat_summary")
@login_required
def get_threat_summary():
    """Fetch curated ThreatDetails summary for the current user."""
    request_id = str(uuid4())
    try:
        severity = request.args.get("severity")
        device_ids_subq = db.session.query(Device.id).filter(Device.user_id == str(current_user.id))

        query = ThreatDetails.query.filter(
            (ThreatDetails.device_id.in_(device_ids_subq)) | (ThreatDetails.device_id.is_(None))
        )

        if severity:
            query = query.filter(ThreatDetails.severity == severity)

        threats = query.order_by(ThreatDetails.detected_at.desc()).all()
        response = {
            "threats": [t.to_dict() for t in threats],
            "request_id": request_id
        }
        current_app.logger.debug(f"Retrieved {len(threats)} threats for summary, RequestID: {request_id}")
        return jsonify(response), 200

    except Exception as e:
        current_app.logger.error(f"get_threat_summary failed: {str(e)}, RequestID: {request_id}")
        return jsonify({"error": str(e), "request_id": request_id}), 500

# -----------------------------
# CORS Headers
# -----------------------------
@threat_bp.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin', 'http://localhost:5000')
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response