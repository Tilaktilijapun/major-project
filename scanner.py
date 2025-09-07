from flask import Blueprint, render_template, request, jsonify, session
from flask_login import LoginManager, login_required, current_user
import asyncio
import uuid
from datetime import datetime
from models import Alert, Threat
from extensions import db

class SecurityScanner:
    def __init__(self, db_session, ml_manager, network_monitor):
        self.db_session = db_session
        self.ml_manager = ml_manager
        self.network_monitor = network_monitor
        self.active_scans = {}

    async def start_scan(self, scan_type: str, user_id: int, params: dict):
        scan_id = str(uuid.uuid4())
        self.active_scans[scan_id] = {'status': 'running', 'results': None, 'started_at': datetime.utcnow()}

        scan_duration = 5 if scan_type == 'quick' else 15
        asyncio.create_task(self._perform_scan(scan_id, user_id, scan_duration, params))
        return {'scan_id': scan_id, 'status': 'started'}

    async def _perform_scan(self, scan_id, user_id, duration, params):
        try:
            await asyncio.sleep(duration)
            devices = self.network_monitor.get_devices(user_id)
            scan_results = []

            for device in devices:
                threat_data = self.network_monitor.collect_device_data(device)
                analysis = self.ml_manager.analyze_threat(threat_data)

                if analysis.get('threat_detected'):
                    threat = Threat(
                        user_id=user_id,
                        device_id=device['id'],
                        type=analysis.get('threat_type', 'Unknown'),
                        severity=analysis.get('severity', 'Low'),
                        description=analysis.get('description', ''),
                        status='Active',
                        created_at=datetime.utcnow()
                    )
                    self.db_session.add(threat)
                    self.db_session.commit()

                    alert = Alert(
                        threat_id=threat.id,
                        user_id=user_id,
                        type=threat.type,
                        message=f"Threat detected on device {device['name']}: {threat.description}",
                        severity=threat.severity,
                        created_at=datetime.utcnow(),
                        read=False
                    )
                    self.db_session.add(alert)
                    self.db_session.commit()

                    scan_results.append({'device': device['name'], 'threat': threat.description})

            self.active_scans[scan_id]['status'] = 'completed'
            self.active_scans[scan_id]['results'] = scan_results
            self.active_scans[scan_id]['completed_at'] = datetime.utcnow()

        except Exception as e:
            self.active_scans[scan_id]['status'] = 'failed'
            self.active_scans[scan_id]['error'] = str(e)

    def get_scan_status(self, scan_id):
        if scan_id not in self.active_scans:
            raise ValueError(f"Scan ID {scan_id} not found")
        return self.active_scans[scan_id]
