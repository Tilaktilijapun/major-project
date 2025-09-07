import time
import docker
from flask import Blueprint, render_template, request, jsonify
from prometheus_client import start_http_server, Gauge, Counter, Histogram
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
from typing import Dict, Any, List
from models import Device, Threat, Alert, UserAlertConfig
from extensions import db
from sqlalchemy import func
from docker.errors import DockerException
from flask_login import login_required, current_user
from threading import Event
from system_metrics import (
    get_cpu_usage, get_cpu_usage_per_core, get_memory_usage, get_disk_usage,
    get_network_io, get_cpu_times, get_memory_info,
    get_disk_io_info, get_network_details, get_system_temperature
)
import logging
import os
import json

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # major project root
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')  # define DATA_DIR first
DATA_PATH = os.path.join(DATA_DIR, 'threats.json')  # then DATA_PATH

# Ensure the data folder exists
os.makedirs(DATA_DIR, exist_ok=True)

# Load threats if file exists, otherwise use empty list
if os.path.exists(DATA_PATH):
    try:
        with open(DATA_PATH, 'r') as f:
            threats = json.load(f).get('threats', [])
    except json.JSONDecodeError as e:
        logging.warning(f"Could not parse {DATA_PATH}: {e}")
        threats = []
else:
    logging.info(f"{DATA_PATH} not found, starting with empty threats list.")
    threats = []


# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z'
)

monitor_instance = None # global

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/monitoring')
@login_required
def monitoring_page():
    return render_template('monitoring.html')

# Prometheus metrics definitions
cpu_usage = Gauge('container_cpu_usage', 'CPU usage by container', ['container'])
memory_usage = Gauge('container_memory_usage', 'Memory usage by container', ['container'])
network_io = Gauge('container_network_io', 'Network I/O by container', ['container', 'direction'])
disk_io = Gauge('container_disk_io', 'Disk I/O by container', ['container', 'operation'])
threat_counter = Counter('security_threats_total', 'Total number of detected threats', ['type', 'severity'])
alert_counter = Counter('security_alerts_total', 'Total number of security alerts', ['type'])
response_time = Histogram('threat_detection_response_time', 'Response time for threat detection')

class SystemMonitor:
    def __init__(self, socketio: SocketIO, app, metrics_interval: int = 5):
        self.socketio = socketio
        self.app = app
        self.metrics_interval = max(1, metrics_interval)
        self._stop_event = Event()
        self.latest_system_metrics = {}   # <-- store latest metrics

        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
        except DockerException as e:
            logging.warning(f"Docker not available: {e}")
            self.docker_client = None

    def calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
            online_cpus = stats['cpu_stats'].get('online_cpus', 1)
            if system_delta > 0 and cpu_delta > 0:
                return (cpu_delta / system_delta) * online_cpus * 100.0
            return 0.0
        except (KeyError, ZeroDivisionError, TypeError):
            return 0.0

    def calculate_memory_percent(self, stats: Dict[str, Any]) -> float:
        try:
            mem_usage = stats['memory_stats']['usage']
            mem_limit = stats['memory_stats']['limit'] or 1
            return (mem_usage / mem_limit) * 100.0
        except (KeyError, ZeroDivisionError, TypeError):
            return 0.0

    def calculate_network_io(self, stats: Dict[str, Any]) -> tuple:
        try:
            networks = stats['networks'] or {}
            total_rx = sum(net.get('rx_bytes', 0) for net in networks.values())
            total_tx = sum(net.get('tx_bytes', 0) for net in networks.values())
            return total_rx, total_tx
        except (KeyError, TypeError):
            return 0, 0

    def calculate_disk_io(self, stats: Dict[str, Any]) -> tuple:
        try:
            blkio_stats = stats.get('blkio_stats', {}).get('io_service_bytes_recursive', []) or []
            read_bytes = sum(item.get('value', 0) for item in blkio_stats if item.get('op') == 'Read')
            write_bytes = sum(item.get('value', 0) for item in blkio_stats if item.get('op') == 'Write')
            return read_bytes, write_bytes
        except (KeyError, TypeError):
            return 0, 0

    def collect_system_metrics(self) -> Dict[str, Any]:
        cpu = get_cpu_usage()
        cpu_per_core = get_cpu_usage_per_core()
        cpu_times = get_cpu_times()
        memory = get_memory_info()
        disk_io = get_disk_io_info()
        network_io = get_network_io()
        temperature = get_system_temperature() or 45.0  # Fallback if None
        total_network = {
            'bytes_sent': sum(stats['bytes_sent'] for stats in network_io.values()),
            'bytes_recv': sum(stats['bytes_recv'] for stats in network_io.values())
        }
        total_disk = {
            'read_count': sum(stats['read_count'] for stats in disk_io.values()),
            'write_count': sum(stats['write_count'] for stats in disk_io.values()),
            'read_bytes': sum(stats['read_bytes'] for stats in disk_io.values()),
            'write_bytes': sum(stats['write_bytes'] for stats in disk_io.values())
        }
        return {
            'cpu': {
                'percent': cpu,
                'per_cpu': [{'core': i, 'percent': percent} for i, percent in enumerate(cpu_per_core)],
                'cpu_times': cpu_times
            },
            'memory': memory,
            'disk_io': {'disk': total_disk},
            'network_io': {'network': total_network},
            'temperature': temperature
        }

    def collect_security_metrics(self) -> Dict[str, Any]:
        session = db.session
        try:
            total_alerts = session.query(func.count(Alert.id)).scalar() or 0
            recent_alerts = session.query(Alert).order_by(Alert.created_at.desc()).limit(5).all() or []
            return {
                'total_alerts': total_alerts,
                'recent_alerts': [{
                    'id': str(alert.id),
                    'category': alert.category,
                    'message': alert.message,
                    'severity': alert.severity,
                    'created_at': alert.created_at.isoformat()
                } for alert in recent_alerts]
            }
        finally:
            session.close()

    def get_user_alert_configs(self) -> List[Dict[str, Any]]:
        session = db.session
        try:
            rows = session.query(UserAlertConfig).all()
            return [{
                'id': str(r.id),
                'user_id': str(r.user_id),
                'metric': r.metric,
                'threshold': float(r.threshold),
                'notification_method': r.notification_method,
                'frequency': r.frequency
            } for r in rows]
        finally:
            session.close()

    def create_alert(self, user_id: str, metric: str, value: float, threshold: float):
        session = db.session
        try:
            severity = 'critical' if value >= (threshold * 1.5) else 'warning'
            message = f"{metric} exceeded: value={value:.2f}, threshold={threshold:.2f}"
            alert = Alert(
                user_id=user_id,
                category=metric,
                message=message,
                severity=severity,
                read=False,
                created_at=datetime.now()
            )
            session.add(alert)
            session.commit()
            alert_counter.labels(type=metric).inc()
            self.socketio.emit('new_alert', {
                'id': str(alert.id),
                'user_id': str(user_id),
                'category': metric,
                'message': message,
                'severity': severity,
                'value': value,
                'threshold': threshold,
                'created_at': alert.created_at.isoformat()
            })
            self.socketio.emit('security_metrics', {
                'total_alerts': session.query(func.count(Alert.id)).scalar() or 0,
                'recent_alerts': [{
                    'id': str(alert.id),
                    'category': alert.category,
                    'message': alert.message,
                    'severity': alert.severity,
                    'created_at': alert.created_at.isoformat()
                } for alert in session.query(Alert).order_by(Alert.created_at.desc()).limit(5).all() or []],
                'alert_config': {
                    'metric': metric,
                    'threshold': threshold,
                    'notification_method': 'email',
                    'frequency': 'immediate'
                },
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            session.rollback()
            logging.error(f"Alert creation error: {e}")
        finally:
            session.close()

    def start_monitoring(self):
        self._stop_event.clear()
        self.socketio.emit('monitoring_status', {'status': 'running', 'timestamp': datetime.now().isoformat()})
        logging.info("[Monitor] Started")
        while not self._stop_event.is_set():
            loop_start = time.perf_counter()
            try:
                # ✅ Add application context here
                with self.app.app_context():
                    system_metrics = self.collect_system_metrics()
                    self.latest_system_metrics = system_metrics  # <-- store snapshot
                    logging.debug(f"System Metrics: {system_metrics}")
                    with response_time.time():
                        security_metrics = self.collect_security_metrics()
                    logging.debug(f"Security Metrics: {security_metrics}")
                    if self.docker_client:
                        try:
                            for container in self.docker_client.containers.list():
                                if 'aivivid' in (container.name or '').lower():
                                    stats = container.stats(stream=False)
                                    cpu_percent = self.calculate_cpu_percent(stats)
                                    cpu_usage.labels(container=container.name).set(cpu_percent)
                                    mem_percent = self.calculate_memory_percent(stats)
                                    memory_usage.labels(container=container.name).set(mem_percent)
                                    rx_bytes, tx_bytes = self.calculate_network_io(stats)
                                    network_io.labels(container=container.name, direction='rx').set(rx_bytes)
                                    network_io.labels(container=container.name, direction='tx').set(tx_bytes)
                                    read_bytes, write_bytes = self.calculate_disk_io(stats)
                                    disk_io.labels(container=container.name, operation='read').set(read_bytes)
                                    disk_io.labels(container=container.name, operation='write').set(write_bytes)
                                    self.socketio.emit('container_metrics', {
                                        'container': container.name,
                                        'cpu': cpu_percent,
                                        'memory': mem_percent,
                                        'network': {'rx': rx_bytes, 'tx': tx_bytes},
                                        'disk': {'read': read_bytes, 'write': write_bytes},
                                        'timestamp': datetime.now().isoformat()
                                    })
                        except Exception as de:
                            logging.error(f"Docker Metrics Error: {de}")
                    now_iso = datetime.now().isoformat()
                    self.socketio.emit('system_metrics', {**system_metrics, 'timestamp': now_iso})
                    self.socketio.emit('security_metrics', {**security_metrics, 'timestamp': now_iso})
                    user_alerts = self.get_user_alert_configs()
                    for alert_cfg in user_alerts:
                        user_id = alert_cfg['user_id']
                        metric = alert_cfg['metric']
                        threshold = alert_cfg['threshold']
                        value = 0.0
                        if metric == 'cpu-usage':
                            value = float(system_metrics.get('cpu', {}).get('percent', 0))
                        elif metric == 'memory-usage':
                            value = float(system_metrics.get('memory', {}).get('virtual_memory', {}).get('percent', 0))
                        elif metric == 'disk-io':
                            disk = system_metrics.get('disk_io', {}).get('disk', {})
                            value = float(disk.get('read_count', 0) + disk.get('write_count', 0))
                        elif metric == 'network-io':
                            net = system_metrics.get('network_io', {}).get('network', {})
                            value = float(net.get('bytes_sent', 0) + net.get('bytes_recv', 0)) / (1024 * 1024)
                        elif metric == 'system-temperature':
                            value = float(system_metrics.get('temperature', 0))
                        if value > threshold:
                            self.create_alert(user_id, metric, value, threshold)
            except Exception as e:
                logging.error(f"Monitoring Error: {e}")

            elapsed = time.perf_counter() - loop_start
            remaining = max(0.0, self.metrics_interval - elapsed)
                
            self.socketio.emit('monitoring_heartbeat', {
                'status': 'running',
                'interval_sec': self.metrics_interval,
                'timestamp': datetime.now().isoformat()
            })
            self.socketio.sleep(remaining if remaining > 0 else 0.001)
        self.socketio.emit('monitoring_status', {'status': 'stopped', 'timestamp': datetime.now().isoformat()})
        logging.info("[Monitor] Stopped")

    def stop_monitoring(self):
        self._stop_event.set()

def init_monitoring(app, socketio: SocketIO, prometheus_port: int = 9100):
    global monitor_instance
    monitor_instance = SystemMonitor(socketio, app)
    try:
        start_http_server(prometheus_port)
        logging.info(f"Prometheus Exporter running on :{prometheus_port}")
    except OSError:
        logging.warning(f"Prometheus Port {prometheus_port} already in use or exporter already running")
    monitor = SystemMonitor(socketio, app)
    @socketio.on('connect')
    def handle_connect():
        emit('connection_status', {'status': 'connected', 'timestamp': datetime.now().isoformat()})
        socketio.start_background_task(monitor.start_monitoring)  # Auto-start monitoring
    @socketio.on('start_monitoring')
    def handle_monitoring_start():
        try:
            socketio.start_background_task(monitor.start_monitoring)
            emit('monitoring_started', {'status': 'success'})
        except Exception as e:
            emit('monitoring_error', {'error': str(e)})
    @socketio.on('stop_monitoring')
    def handle_monitoring_stop():
        try:
            monitor.stop_monitoring()
            emit('monitoring_stopped', {'status': 'success'})
        except Exception as e:
            emit('monitoring_error', {'error': str(e)})
    @app.route('/api/monitoring/metrics')
    def get_system_metrics():
        try:
            system_metrics = monitor.collect_system_metrics()
            return {
                'system': system_metrics,
                'security': monitor.collect_security_metrics(),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error in get_system_metrics: {e}")
            return {'error': str(e)}, 500
    @app.route('/api/monitoring/containers')
    def get_container_metrics():
        try:
            if not monitor.docker_client:
                return {'error': 'Docker not available'}, 503
            containers = monitor.docker_client.containers.list()
            container_stats = []
            for container in containers:
                stats = container.stats(stream=False)
                container_stats.append({
                    'id': container.id,
                    'name': container.name,
                    'cpu': monitor.calculate_cpu_percent(stats),
                    'memory': monitor.calculate_memory_percent(stats),
                    'network': monitor.calculate_network_io(stats),
                    'disk': monitor.calculate_disk_io(stats),
                    'status': container.status
                })
            return {
                'containers': container_stats,
                'total': len(container_stats),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error in get_container_metrics: {e}")
            return {'error': str(e)}, 500
    @app.route('/api/monitoring/alerts/summary')
    def get_alert_summary():
        try:
            session = db.session
            try:
                total_alerts = session.query(func.count(Alert.id)).scalar() or 0
                critical_alerts = session.query(func.count(Alert.id)).filter(Alert.severity == 'critical').scalar() or 0
                unread_alerts = session.query(func.count(Alert.id)).filter(Alert.read == False).scalar() or 0
                recent_alerts = session.query(Alert).order_by(Alert.created_at.desc()).limit(5).all() or []
                return {
                    'summary': {
                        'total': total_alerts,
                        'critical': critical_alerts,
                        'unread': unread_alerts
                    },
                    'recent': [{
                        'id': str(alert.id),
                        'category': alert.category,
                        'message': alert.message,
                        'severity': alert.severity,
                        'created_at': alert.created_at.isoformat()
                    } for alert in recent_alerts]
                }
            finally:
                session.close()
        except Exception as e:
            logging.error(f"Error in get_alert_summary: {e}")
            return {'error': str(e)}, 500
    @app.route('/api/monitoring/performance')
    def get_performance_metrics():
        try:
            return {
                'cpu': get_cpu_times(),
                'per_cpu': get_cpu_usage_per_core(),
                'memory': get_memory_info(),
                'disk': get_disk_io_info(),
                'network': get_network_details(),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logging.error(f"Error in get_performance_metrics: {e}")
            return {'error': str(e)}, 500
    @app.route('/api/monitoring/alerts/config', methods=['POST'])
    @login_required
    def configure_alert():
        try:
            data = request.json
            required_keys = ['metric', 'threshold', 'notification_method', 'frequency']
            if not data or not all(k in data for k in required_keys):
                return jsonify({'error': 'Missing required fields'}), 400
            metric = data['metric']
            threshold = float(data['threshold'])
            notification_method = data['notification_method']
            frequency = data['frequency']
            valid_metrics = ['cpu-usage', 'memory-usage', 'disk-io', 'network-io', 'system-temperature']
            valid_notifications = ['email', 'sms', 'push']
            valid_frequencies = ['immediate', 'hourly', 'daily']
            if metric not in valid_metrics:
                return jsonify({'error': f'Invalid metric. Must be one of {valid_metrics}'}), 400
            if not 0 <= threshold <= 100:
                return jsonify({'error': 'Threshold must be between 0 and 100'}), 400
            if notification_method not in valid_notifications:
                return jsonify({'error': f'Invalid notification method. Must be one of {valid_notifications}'}), 400
            if frequency not in valid_frequencies:
                return jsonify({'error': f'Invalid frequency. Must be one of {valid_frequencies}'}), 400
            alert_config = UserAlertConfig(
                user_id=current_user.id,
                metric=metric,
                threshold=threshold,
                notification_method=notification_method,
                frequency=frequency
            )
            db.session.add(alert_config)
            db.session.commit()
            socketio.emit('security_metrics', {
                'alert_config': {
                    'id': str(alert_config.id),
                    'user_id': str(alert_config.user_id),
                    'metric': alert_config.metric,
                    'threshold': float(alert_config.threshold),
                    'notification_method': alert_config.notification_method,
                    'frequency': alert_config.frequency
                },
                'timestamp': datetime.now().isoformat()
            })
            return jsonify({
                'message': 'Alert configuration saved successfully',
                'config': {
                    'id': str(alert_config.id),
                    'user_id': str(alert_config.user_id),
                    'metric': alert_config.metric,
                    'threshold': float(alert_config.threshold),
                    'notification_method': alert_config.notification_method,
                    'frequency': alert_config.frequency
                }
            })
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error in configure_alert: {e}")
            return jsonify({'error': str(e)}), 500
        
    return monitor_instance

def get_latest_metrics(user_id=None):
    """Return latest monitoring metrics (devices, threats, alerts) for dashboard use."""
    query_filter = []
    if user_id:
        query_filter.append(Device.user_id == user_id)

    devices_count = db.session.query(func.count(Device.id)).filter(*query_filter).scalar()
    active_threats = db.session.query(func.count(Threat.id)).filter(*query_filter).scalar()
    alerts_count = db.session.query(func.count(Alert.id)).filter(*query_filter).scalar()

    return {
        "devices_count": devices_count,
        "active_threats": active_threats,
        "alerts_count": alerts_count
    }