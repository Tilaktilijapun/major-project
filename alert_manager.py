# AIVivid Alert and Notification Manager

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import redis
from fastapi import WebSocket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Alert:
    id: str
    type: str
    severity: str
    source: str
    description: str
    timestamp: str
    status: str
    details: Dict[str, Union[str, float, int]]
    recommendations: List[str]

class AlertManager:
    def __init__(self, redis_url: str = 'redis://localhost:6379/0'):
        self.redis_client = redis.from_url(redis_url)
        self.active_websockets: List[WebSocket] = []
        self.alert_handlers = {
            'network': self._handle_network_alert,
            'security': self._handle_security_alert,
            'system': self._handle_system_alert,
            'threat': self._handle_threat_alert
        }
        self.severity_thresholds = {
            'critical': 1,
            'high': 5,
            'medium': 15,
            'low': 30
        }

    async def register_websocket(self, websocket: WebSocket):
        """Register a new WebSocket connection."""
        await websocket.accept()
        self.active_websockets.append(websocket)
        logger.info(f"New WebSocket connection registered. Total connections: {len(self.active_websockets)}")

    async def unregister_websocket(self, websocket: WebSocket):
        """Unregister a WebSocket connection."""
        if websocket in self.active_websockets:
            self.active_websockets.remove(websocket)
            logger.info(f"WebSocket connection unregistered. Remaining connections: {len(self.active_websockets)}")

    async def broadcast_alert(self, alert: Alert):
        """Broadcast alert to all connected WebSocket clients."""
        message = json.dumps(asdict(alert))
        disconnected_sockets = []

        for websocket in self.active_websockets:
            try:
                await websocket.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {str(e)}")
                disconnected_sockets.append(websocket)

        # Clean up disconnected sockets
        for websocket in disconnected_sockets:
            await self.unregister_websocket(websocket)

    async def process_alert(self, alert_data: Dict) -> Alert:
        """Process incoming alert data and create an Alert object."""
        try:
            alert = Alert(
                id=alert_data.get('id', str(datetime.now().timestamp())),
                type=alert_data['type'],
                severity=alert_data['severity'],
                source=alert_data['source'],
                description=alert_data['description'],
                timestamp=datetime.now().isoformat(),
                status='new',
                details=alert_data.get('details', {}),
                recommendations=alert_data.get('recommendations', [])
            )

            # Store alert in Redis
            self.redis_client.hset(
                f"alert:{alert.id}",
                mapping=asdict(alert)
            )

            # Handle alert based on type
            handler = self.alert_handlers.get(alert.type)
            if handler:
                await handler(alert)

            # Broadcast alert to connected clients
            await self.broadcast_alert(alert)

            return alert

        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
            raise

    async def _handle_network_alert(self, alert: Alert):
        """Handle network-related alerts."""
        if alert.severity in ['critical', 'high']:
            await self._send_email_notification(alert)
            await self._update_security_metrics(alert)

    async def _handle_security_alert(self, alert: Alert):
        """Handle security-related alerts."""
        if alert.severity in ['critical', 'high']:
            await self._send_email_notification(alert)
            await self._trigger_security_response(alert)

    async def _handle_system_alert(self, alert: Alert):
        """Handle system-related alerts."""
        if alert.severity == 'critical':
            await self._send_email_notification(alert)
            await self._trigger_system_maintenance(alert)

    async def _handle_threat_alert(self, alert: Alert):
        """Handle threat-related alerts."""
        if alert.severity in ['critical', 'high']:
            await self._send_email_notification(alert)
            await self._trigger_threat_response(alert)

    async def _send_email_notification(self, alert: Alert):
        """Send email notification for critical alerts."""
        try:
            # Email configuration (should be moved to environment variables)
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            sender_email = 'your-email@gmail.com'
            sender_password = 'your-app-specific-password'
            recipient_email = 'admin@example.com'

            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = f"[{alert.severity.upper()}] {alert.type} Alert"

            # Create HTML body
            html_body = f"""
            <html>
                <body>
                    <h2>Alert Details</h2>
                    <p><strong>Type:</strong> {alert.type}</p>
                    <p><strong>Severity:</strong> {alert.severity}</p>
                    <p><strong>Source:</strong> {alert.source}</p>
                    <p><strong>Description:</strong> {alert.description}</p>
                    <p><strong>Timestamp:</strong> {alert.timestamp}</p>
                    <h3>Recommendations:</h3>
                    <ul>
                        {''.join(f'<li>{r}</li>' for r in alert.recommendations)}
                    </ul>
                </body>
            </html>
            """

            msg.attach(MIMEText(html_body, 'html'))

            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(msg)

            logger.info(f"Email notification sent for alert {alert.id}")

        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")

    async def _update_security_metrics(self, alert: Alert):
        """Update security metrics based on alert."""
        try:
            metrics_key = f"security_metrics:{datetime.now().strftime('%Y-%m-%d')}"
            self.redis_client.hincrby(metrics_key, f"alerts_{alert.severity}", 1)
            self.redis_client.hincrby(metrics_key, f"alerts_{alert.type}", 1)
        except Exception as e:
            logger.error(f"Error updating security metrics: {str(e)}")

    async def _trigger_security_response(self, alert: Alert):
        """Trigger automated security response based on alert."""
        # Implement security response logic here
        pass

    async def _trigger_system_maintenance(self, alert: Alert):
        """Trigger system maintenance tasks based on alert."""
        # Implement system maintenance logic here
        pass

    async def _trigger_threat_response(self, alert: Alert):
        """Trigger threat response actions based on alert."""
        # Implement threat response logic here
        pass

    async def get_alerts(self, 
                        alert_type: Optional[str] = None,
                        severity: Optional[str] = None,
                        status: Optional[str] = None,
                        limit: int = 100) -> List[Alert]:
        """Retrieve alerts with optional filtering."""
        try:
            alerts = []
            for key in self.redis_client.scan_iter("alert:*"):
                alert_data = self.redis_client.hgetall(key)
                if alert_data:
                    # Convert Redis hash to Alert object
                    alert = Alert(
                        id=alert_data.get(b'id', b'').decode('utf-8'),
                        type=alert_data.get(b'type', b'').decode('utf-8'),
                        severity=alert_data.get(b'severity', b'').decode('utf-8'),
                        source=alert_data.get(b'source', b'').decode('utf-8'),
                        description=alert_data.get(b'description', b'').decode('utf-8'),
                        timestamp=alert_data.get(b'timestamp', b'').decode('utf-8'),
                        status=alert_data.get(b'status', b'').decode('utf-8'),
                        details=json.loads(alert_data.get(b'details', b'{}')),
                        recommendations=json.loads(alert_data.get(b'recommendations', b'[]'))
                    )

                    # Apply filters
                    if alert_type and alert.type != alert_type:
                        continue
                    if severity and alert.severity != severity:
                        continue
                    if status and alert.status != status:
                        continue

                    alerts.append(alert)

                    if len(alerts) >= limit:
                        break

            return alerts

        except Exception as e:
            logger.error(f"Error retrieving alerts: {str(e)}")
            raise

    async def update_alert_status(self, alert_id: str, new_status: str) -> Optional[Alert]:
        """Update the status of an alert."""
        try:
            alert_key = f"alert:{alert_id}"
            if not self.redis_client.exists(alert_key):
                return None

            # Update status in Redis
            self.redis_client.hset(alert_key, 'status', new_status)

            # Get updated alert
            alert_data = self.redis_client.hgetall(alert_key)
            alert = Alert(
                id=alert_data.get(b'id', b'').decode('utf-8'),
                type=alert_data.get(b'type', b'').decode('utf-8'),
                severity=alert_data.get(b'severity', b'').decode('utf-8'),
                source=alert_data.get(b'source', b'').decode('utf-8'),
                description=alert_data.get(b'description', b'').decode('utf-8'),
                timestamp=alert_data.get(b'timestamp', b'').decode('utf-8'),
                status=new_status,
                details=json.loads(alert_data.get(b'details', b'{}')),
                recommendations=json.loads(alert_data.get(b'recommendations', b'[]'))
            )

            # Broadcast update
            await self.broadcast_alert(alert)

            return alert

        except Exception as e:
            logger.error(f"Error updating alert status: {str(e)}")
            raise

# Example usage
if __name__ == '__main__':
    async def main():
        alert_manager = AlertManager()

        # Create sample alert
        sample_alert = {
            'type': 'security',
            'severity': 'high',
            'source': 'firewall',
            'description': 'Suspicious network activity detected',
            'details': {
                'source_ip': '192.168.1.100',
                'destination_ip': '10.0.0.5',
                'port': 445
            },
            'recommendations': [
                'Block source IP address',
                'Update firewall rules',
                'Monitor for similar patterns'
            ]
        }

        # Process alert
        alert = await alert_manager.process_alert(sample_alert)
        print(f"Processed alert: {alert}")

        # Retrieve alerts
        alerts = await alert_manager.get_alerts(severity='high')
        print(f"\nRetrieved {len(alerts)} high severity alerts")

    asyncio.run(main())