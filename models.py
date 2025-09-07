from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import datetime
import uuid
import re
from extensions import db, func
from sqlalchemy.dialects.postgresql import JSONB


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    location = db.Column(db.String(100))
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_subscribed = db.Column(db.Boolean, default=False, nullable=False)
    is_demo_active = db.Column(db.Boolean, default=False, nullable=False)
    demo_start_date = db.Column(db.DateTime, nullable=True)
    is_active_account = db.Column(db.Boolean, default=True, nullable=False)

    # ✅ Fixed notification_preferences relationship
    notification_preferences = db.relationship(
        'NotificationPreference',
        uselist=False,
        back_populates='user',
        overlaps="notification_preferences"
    )

    devices = db.relationship('Device', backref='owner', lazy='dynamic')
    activity_logs = db.relationship('ActivityLog', backref='user', lazy='dynamic')
    alerts = db.relationship('Alert', backref='user', lazy='dynamic')
    posts = db.relationship('BlogPost', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Override Flask-Login's active check
    def is_active(self):
        if self.role == "admin":
            return True
        return self.is_active_account

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat(),
            'is_subscribed': self.is_subscribed,
            'is_demo_active': self.is_demo_active,
            'demo_start_date': self.demo_start_date.isoformat() if self.demo_start_date else None,
            'is_active_account': self.is_active(),
            'posts': [post.to_dict() for post in self.posts]
        }

class Device(db.Model):
    __tablename__ = 'devices'

    # Primary key as VARCHAR
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Required foreign key to user
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)

    # Device details
    name = db.Column(db.String(255), nullable=False, default='Unknown')
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(50), nullable=False, default='unknown')
    detected_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    model_id = db.Column(db.Integer, db.ForeignKey('ml_models.id'), nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='detected')

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'detected_at': self.detected_at.isoformat() if self.detected_at else None,
            'model_id': self.model_id,
            'ip_address': self.ip_address,
            'port': self.port,
            'protocol': self.protocol,
            'status': self.status
        }

class DeviceActivityLog(db.Model):
    __tablename__ = 'device_activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # Add this line
    ip_address = db.Column(db.String(45), nullable=False)
    protocol = db.Column(db.String(50), nullable=True)
    activity = db.Column(db.String(255), nullable=True)
    anomaly_score = db.Column(db.Float, nullable=True)
    threat_detected = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String(50), default='Normal')  # ✅ add this line
    
    # Optional: link to Device table if you want to associate it
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,  # include it here too
            "ip_address": self.ip_address,
            "protocol": self.protocol,
            "activity": self.activity,
            "anomaly_score": self.anomaly_score,
            "threat_detected": self.threat_detected,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "device_id": self.device_id
        }

class Threat(db.Model):
        __tablename__ = 'threats'

        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        name = db.Column(db.String(128), nullable=False)
        type = db.Column(db.String(64))
        description = db.Column(db.Text)
        severity = db.Column(db.String(20))
        detected_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        status = db.Column(db.String(20), default='Active')
        affected_device = db.Column(db.String(36), db.ForeignKey('devices.id'))
        indicator = db.Column(db.String(128))
        recommended_action = db.Column(db.Text)
        ip_address = db.Column(db.String(45), nullable=True)  # Added for IPv4/IPv6
        port = db.Column(db.Integer, nullable=True)  # Added for port number
        protocol = db.Column(db.String(20), nullable=True)  # Added for protocol


        def to_dict(self):
            return {
                'id': self.id,
                'name': self.name,
                'type': self.type,
                'description': self.description,
                'severity': self.severity,
                'detected_at': self.detected_at.isoformat(),
                'status': self.status,
                'affected_device': self.affected_device,
                'indicator': self.indicator,
                'recommended_action': self.recommended_action,
                'ip_address': self.ip_address,
                'port': self.port,
                'protocol': self.protocol
            }

class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_id = db.Column(db.String(36), db.ForeignKey('threat_details.id'))  # Updated FK
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))  # Changed from UUID
    title = db.Column(db.String(128), nullable=False)
    message = db.Column(db.Text)
    severity = db.Column(db.String(50))  # Added severity column
    category = db.Column(db.String(50))  # Added category column
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    false_positive = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': str(self.id),
            'threat_id': str(self.threat_id) if self.threat_id else None,
            'user_id': str(self.user_id) if self.user_id else None,
            'title': self.title,
            'message': self.message,
            'severity': self.severity,
            'category': self.category,
            'created_at': self.created_at.isoformat(),
            'read': self.read,
            'false_positive': self.false_positive
        }


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    activity = db.Column(db.String(64), nullable=False)  # renamed from action_type
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(10))  # e.g., TCP, UDP

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'activity': self.activity,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'port': self.port,
            'protocol': self.protocol
        }

class SystemLog(db.Model):
        __tablename__ = 'system_logs'

        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        log_level = db.Column(db.String(20))
        message = db.Column(db.Text)
        timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        source = db.Column(db.String(128))
        type = db.Column(db.String(64))

        def to_dict(self):
            return {
                'id': self.id,
                'log_level': self.log_level,
                'message': self.message,
                'timestamp': self.timestamp.isoformat(),
                'source': self.source,
                'type': self.type
            }

class PricingPlans(db.Model):
        __tablename__ = 'pricing_plans'
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(50), nullable=False)
        price = db.Column(db.Numeric(10, 2), nullable=False)
        billing_cycle = db.Column(db.String(20), nullable=False)  # e.g. 'Monthly'
        features = db.Column(db.Text, nullable=False)
        description = db.Column(db.Text)
        duration_days = db.Column(db.Integer, default=30, nullable=False)
        status = db.Column(db.String(50), nullable=False, default='active')
        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        def to_dict(self):
            return {
                'id': self.id,
                'name': self.name,
                'price': float(self.price),  # Convert Decimal to float
                'billing_cycle': self.billing_cycle,
                'features': self.features.split(', '),  # optional: return as a list
                'description': self.description,
                'duration_days': self.duration_days,
                'status': self.status,
                'created_at': self.created_at.isoformat() if self.created_at else None
            }

class demo(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
        used_at = db.Column(db.DateTime, nullable=True)
        status = db.Column(db.String(50), default='unused')
        notes = db.Column(db.Text)

        
        def to_dict(self):
            return {
            'id': self.id,
            'user_id': self.user_id,
            'used_at': self.used_at.isoformat() if self.used_at else None,
            'status': self.status,
            'notes': self.notes
        }

class MLManager(db.Model):
    __tablename__ = 'ml_managers'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_model_path = db.Column(db.String(255))
    device_scaler_path = db.Column(db.String(255))
    threat_model_path = db.Column(db.String(255))
    threat_scaler_path = db.Column(db.String(255))

    predictions = db.relationship('Prediction', back_populates='model')

    def __init__(self, device_model_path, device_scaler_path, threat_model_path, threat_scaler_path):
        self.device_model_path = device_model_path
        self.device_scaler_path = device_scaler_path
        self.threat_model_path = threat_model_path
        self.threat_scaler_path = threat_scaler_path

        # Load models/scalers dynamically only if needed (not stored in DB)
        self.device_model = load_model(device_model_path)
        self.threat_model = load_model(threat_model_path)
        with open(device_scaler_path, 'rb') as f1:
            self.device_scaler = joblib.load(f1)
        with open(threat_scaler_path, 'rb') as f2:
            self.threat_scaler = joblib.load(f2)


class Prediction(db.Model):
    __tablename__ = 'predictions'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_id = db.Column(db.String(36), db.ForeignKey('ml_managers.id'), nullable=True)
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    is_accurate = db.Column(db.Boolean, default=False)
    is_false_positive = db.Column(db.Boolean, default=False)
    is_false_negative = db.Column(db.Boolean, default=False)
    result = db.Column(db.JSON)

    # FIX: Change backref name from 'model' to 'ml_predictions'
    model = db.relationship('MLManager', back_populates='predictions')
    device = db.relationship('Device', backref=db.backref('predictions', lazy=True))

    def to_dict(self):
            return {
                'id': self.id,
                'model_id': self.model_id,
                'device_id': self.device_id,
                'timestamp': self.timestamp.isoformat(),
                'is_accurate': self.is_accurate,
                'is_false_positive': self.is_false_positive,
                'is_false_negative': self.is_false_negative,
                'result': self.result
            }
class ThreatModel(db.Model):
        __tablename__ = 'threat_models'

        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        model_name = db.Column(db.String(100), unique=True, nullable=False)
        status = db.Column(db.String(50), nullable=False, default='idle')
        last_trained = db.Column(db.DateTime)
        parameters = db.Column(db.JSON)
        threat_level = db.Column(db.String(50), default='medium')

        def to_dict(self):
            return {
                'id': self.id,
                'model_name': self.model_name,
                'status': self.status,
                'last_trained': self.last_trained.isoformat() if self.last_trained else None,
                'parameters': self.parameters,
                'threat_level': self.threat_level
            }

class Subscription(db.Model):
        __tablename__ = 'subscriptions'

        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
        plan_id = db.Column(db.String(36), db.ForeignKey('pricing_plans.id'), nullable=False)
        status = db.Column(db.String(50), nullable=False, default='active')
        start_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
        end_date = db.Column(db.DateTime)
        created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

        def to_dict(self):
            return {
                'id': self.id,
                'user_id': self.user_id,
                'plan_id': self.plan_id,
                'status': self.status,
                'start_date': self.start_date.isoformat() if self.start_date else None,
                'end_date': self.end_date.isoformat() if self.end_date else None,
                'created_at': self.created_at.isoformat() if self.created_at else None
            }

class ContactMessage(db.Model):
    __tablename__ = 'contact_messages'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # Already correct
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default='unread')
    user = db.relationship('User', backref=db.backref('contact_messages', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'message': self.message,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'status': self.status,
            'user': self.user.to_dict() if self.user else None
        }

class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # Changed from UUID
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    read = db.Column(db.Boolean, nullable=False, default=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.datetime.utcnow)
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': str(self.user_id),
            'title': self.title,
            'message': self.message,
            'read': self.read,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
class NotificationPreference(db.Model):
    __tablename__ = 'notification_preferences'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    email_enabled = db.Column(db.Boolean, nullable=False, default=True)
    sms_enabled = db.Column(db.Boolean, nullable=False, default=False)
    push_enabled = db.Column(db.Boolean, nullable=False, default=True)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=datetime.datetime.utcnow,
        onupdate=datetime.datetime.utcnow
    )

    # Fix for SAWarning: specify overlaps
    user = db.relationship('User', back_populates='notification_preferences', overlaps="notification_preferences")

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': str(self.user_id),
            'email_enabled': self.email_enabled,
            'sms_enabled': self.sms_enabled,
            'push_enabled': self.push_enabled,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Recommendation(db.Model):
    __tablename__ = 'recommendations'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # Changed from UUID to String(36)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = db.relationship('User')  # Optional: add backref='recommendations' for reverse access

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': str(self.user_id),
            'title': self.title,
            'content': self.content,
            'category': self.category,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # Changed from UUID
    event_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.datetime.utcnow)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = db.relationship('User')

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': str(self.user_id),
            'event_type': self.event_type,
            'description': self.description,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class ThreatDetails(db.Model):
    __tablename__ = 'threat_details'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(64))
    description = db.Column(db.Text)
    severity = db.Column(db.String(50))
    detected_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    device_id = db.Column(db.String(36), db.ForeignKey('devices.id'))
    model_id = db.Column(db.String(36), db.ForeignKey('threat_models.id')) # Optional if linked to a model
    affected_device = db.Column(db.String(36), db.ForeignKey('devices.id'))
    indicator = db.Column(db.String(128))
    recommended_action = db.Column(db.Text)
    ip_address = db.Column(db.String(45))  # Supports IPv4/IPv6
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    status = db.Column(db.String(50), default='detected')  # Added for mitigation

    alerts = db.relationship("Alert", backref="threat_detail", lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'description': self.description,
            'severity': self.severity,
            'detected_at': self.detected_at.isoformat(),
            'device_id': self.device_id,
            'model_id': self.model_id,
            'affected_device': self.affected_device,
            'indicator': self.indicator,
            'recommended_action': self.recommended_action,
            'ip_address': self.ip_address,
            'port': self.port,
            'protocol': self.protocol,
            'status': self.status
        }

import uuid
import datetime
from extensions import db
from sqlalchemy.dialects.postgresql import JSONB

class MLModel(db.Model):
    __tablename__ = 'ml_models'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False, unique=True)  # Can serve as version
    type = db.Column(db.String(50), nullable=False, default="generic")  # e.g., "classification", "regression"
    status = db.Column(db.String(50), default='idle')
    trained_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_trained = db.Column(db.DateTime, nullable=True)  # Updates on retraining
    version = db.Column(db.Integer, nullable=False, default=1)  # versioning for retraining
    parameters = db.Column(JSONB, nullable=False)  # Use JSONB for PostgreSQL
    accuracy = db.Column(db.Float, nullable=False)
    training_samples = db.Column(db.Integer, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'status': self.status,
            'trained_at': self.trained_at.isoformat() if self.trained_at else None,
            'last_trained': self.last_trained.isoformat() if self.last_trained else None,
            'version': self.version,
            'parameters': self.parameters,
            'accuracy': self.accuracy,
            'training_samples': self.training_samples if self.trained_at else None
        }


class ThreatPrediction(db.Model):
    __tablename__ = 'threat_predictions'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    threat_id = db.Column(db.String(36), db.ForeignKey('threat_details.id'), nullable=False)
    predicted_level = db.Column(db.String(50), nullable=False)  # e.g. 'low', 'medium', 'high'
    confidence_score = db.Column(db.Float)  # e.g. 0.85 for 85%
    predicted_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    model_id = db.Column(db.String(36), db.ForeignKey('ml_models.id'))  # which model made prediction
    notes = db.Column(db.Text)  # optional extra info

    def to_dict(self):
        return {
            'id': self.id,
            'threat_id': self.threat_id,
            'predicted_level': self.predicted_level,
            'confidence_score': self.confidence_score,
            'predicted_at': self.predicted_at.isoformat(),
            'model_id': self.model_id,
            'notes': self.notes
        }

class BlogPost(db.Model):
    __tablename__ = 'blog_posts'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.String(36), db.ForeignKey('users.id'))  # Match UUID string type
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    is_published = db.Column(db.Boolean, default=False)
    category = db.Column(db.String(50), nullable=True)  # new column
    image_url = db.Column(db.String(255), nullable=True)  # new column

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'author_id': self.author_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'is_published': self.is_published,
            'category': self.category,
            'image_url': self.image_url,
        }

class ChatLog(db.Model):
    __tablename__ = 'chat_logs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # assuming users.id is Integer
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'response': self.response,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat()
        }

class ModelTrainingHistory(db.Model):
    __tablename__ = 'model_training_history'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    model_id = db.Column(db.Integer, db.ForeignKey('ml_models.id'), nullable=False)# <-- Foreign key
    model_name = db.Column(db.String(100), nullable=False)
    version = db.Column(db.Integer, nullable=False)  # <-- integer version
    status = db.Column(db.String(50), nullable=False, default='pending')  # <-- Added status
    accuracy = db.Column(db.Float, nullable=False)
    loss = db.Column(db.Float, nullable=False)
    trained_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    trained_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)  # <-- New column
    total_epochs = db.Column(db.Integer, nullable=False, default=0)
    duration = db.Column(db.Float, nullable=True)  # <-- New column, store duration in seconds

    # Relationship
    model = db.relationship('MLModel', backref=db.backref('training_history', lazy='dynamic'))

    def to_dict(self):
        return {
            'id': self.id,
            'model_id': self.model_id,
            'model_name': self.model_name,
            'version': self.version,
            'status': self.status,
            'accuracy': self.accuracy,
            'loss': self.loss,
            'trained_by': self.trained_by,
            'trained_at': self.trained_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_epochs': self.total_epochs,
            'duration': self.duration
        }

class Payment(db.Model):
    __tablename__ = 'payments'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False)  # e.g., "success", "pending", "failed"
    payment_method = db.Column(db.String(50), nullable=False)  # e.g., "Credit Card", "Stripe", etc.
    transaction_id = db.Column(db.String(100), unique=True, nullable=False)
    paid_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'amount': self.amount,
            'status': self.status,
            'payment_method': self.payment_method,
            'transaction_id': self.transaction_id,
            'paid_at': self.paid_at.isoformat()
        }
# ---------------------------
# Security Scan Data Model
# ---------------------------
class SecurityScanResult(db.Model):
    __tablename__ = 'security_scan_results'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)  # ✅ String(36)
    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    details = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'status': self.status,
            'severity': self.severity,
            'details': self.details or {},
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }


# ---------------------------
# Security Alerts Model
# ---------------------------
class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.String, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50))
    category = db.Column(db.String(100))  # ✅ new column
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': str(self.user_id),
            'title': self.title,
            'message': self.message,
            'severity': self.severity,
            'category': self.category,   # ✅ added to output
            'created_at': self.created_at.isoformat(),
            'read': self.read
        }

# ---------------------------
# Live Monitoring Data Model
# ---------------------------
class MonitoringData(db.Model):
    __tablename__ = 'monitoring_data'

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(db.String, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    memory_usage = db.Column(db.Float)
    network_activity = db.Column(db.JSON)  # Store as structured JSON
    device_status = db.Column(db.String(100))

    def to_dict(self):
        return {
            'id': str(self.id),
            'user_id': str(self.user_id),
            'timestamp': self.timestamp.isoformat(),
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'network_activity': self.network_activity,
            'device_status': self.device_status
        }

class UserAlertConfig(db.Model):
    __tablename__ = 'user_alert_configs'

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    metric = db.Column(db.String(50), nullable=False)  # e.g., 'cpu-usage', 'network-traffic'
    threshold = db.Column(db.Float, nullable=False)  # 0-100
    notification_method = db.Column(db.String(20), nullable=False)  # 'email', 'sms', 'push'
    frequency = db.Column(db.String(20), nullable=False)  # 'immediate', 'hourly', 'daily'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    user = db.relationship('User', backref=db.backref('alert_configs', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'metric': self.metric,
            'threshold': self.threshold,
            'notification_method': self.notification_method,
            'frequency': self.frequency,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class AccessRequest(db.Model):
    """AccessRequest model for managing user access requests."""
    __tablename__ = 'access_requests'
    id = db.Column(db.String(36), primary_key=True)  # UUID or string ID
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    device_name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # Supports IPv4/IPv6
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='Pending', nullable=False)  # Pending, Allowed, Denied

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'device_name': self.device_name,
            'ip_address': self.ip_address,
            'created_at': self.created_at,
            'description': self.description,
            'status': self.status
        }
class Analytics(db.Model):
    __tablename__ = 'analytics'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    metric_name = db.Column(db.String(50), nullable=False)   # e.g., 'threats_blocked', 'avg_detection_time'
    metric_value = db.Column(db.Float, nullable=False)
    period_start = db.Column(db.DateTime, nullable=False)    # start of the period
    period_end = db.Column(db.DateTime, nullable=False)      # end of the period
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
