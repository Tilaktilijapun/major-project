from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
import numpy as np
import joblib
from datetime import datetime
import os

from flask import Blueprint, request, jsonify, render_template, current_app
from flask_login import login_required, current_user

from models import MLModel, ThreatPrediction, ThreatDetails
from extensions import db
from sqlalchemy import text

# Define model directory
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_models')

# Debug prints
print("Current working directory:", os.getcwd())
print("MODEL_DIR:", MODEL_DIR)
print("Device model exists:", os.path.exists(os.path.join(MODEL_DIR, 'device_model.h5')))
print("Threat model exists:", os.path.exists(os.path.join(MODEL_DIR, 'threat_model.h5')))
print("Scaler device exists:", os.path.exists(os.path.join(MODEL_DIR, 'scaler_device.pkl')))
print("Scaler threat exists:", os.path.exists(os.path.join(MODEL_DIR, 'scaler_threat.pkl')))

model_bp = Blueprint('model', __name__)

class ThreatDetectionModel:
    def __init__(self, model_file='threat_model.h5', scaler_file='scaler.pkl'):
        model_path = os.path.join(MODEL_DIR, model_file)
        scaler_path = os.path.join(MODEL_DIR, scaler_file)

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at {model_path}")
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"Scaler file not found at {scaler_path}")

        self.model = load_model(model_path)
        self.scaler = joblib.load(scaler_path)
        self.max_sequence_length = 100
        self.threshold = 0.5

    def preprocess_features(self, features):
        # Use scaler's expected feature names if available
        if hasattr(self.scaler, 'feature_names_in_'):
            feature_order = self.scaler.feature_names_in_
        else:
            # Fallback order, adjust to match what was used during training
            feature_order = ['packet_rate', 'byte_rate', 'packet_size', 'protocol_type', 'flow_duration']

        # Fill missing features with 0
        numerical_features = np.array([features.get(f, 0) for f in feature_order]).reshape(1, -1)
        scaled_features = self.scaler.transform(numerical_features)

        # Handle sequence input if any
        if 'sequence_data' in features:
            sequence = pad_sequences(
                [features['sequence_data']],
                maxlen=self.max_sequence_length,
                padding='post'
            )
            return [scaled_features, sequence]

        return scaled_features

    def predict(self, features, model_type):
        processed_features = self.preprocess_features(features)
        prediction = self.model.predict(processed_features)
        score = float(prediction[0][0])
        is_threat = score > self.threshold
        threat_level = 'high' if score > 0.9 else 'medium' if score > 0.7 else 'low'

        # Get the latest model ID for this type
        model_record = MLModel.query.filter(MLModel.parameters.op('@>')(text(f"'{{ \"type\": \"{model_type}\" }}'::jsonb"))).order_by(MLModel.trained_at.desc()).first()

        # Log into ThreatDetails
        threat_detail = ThreatDetails(
            name=f"AutoDetected {model_type.capitalize()}",
            description=f"Automatically detected from {model_type} data",
            severity=threat_level,
            detected_at=datetime.utcnow(),
            device_id=features.get('device_id'),
            model_id=model_record.id if model_record else None,
            status='detected'
        )
        db.session.add(threat_detail)
        db.session.flush()

        # Log into ThreatPrediction
        prediction_record = ThreatPrediction(
            threat_id=threat_detail.id,
            predicted_level=threat_level,
            confidence_score=score,
            predicted_at=datetime.utcnow(),
            model_id=model_record.id if model_record else None,
            notes=f"Inference via {model_type.capitalize()}DetectionModel"
        )
        db.session.add(prediction_record)
        db.session.commit()

        return {
            'is_threat': is_threat,
            'confidence': score,
            'prediction_id': prediction_record.id,
            'threat_id': threat_detail.id
        }

    def update_threshold(self, new_threshold):
        self.threshold = new_threshold

# Initialize models
_device_model = None
_threat_model = None

def initialize_models():
    global _device_model, _threat_model
    try:
        _device_model = ThreatDetectionModel('device_model.h5', 'scaler_device.pkl')
        print("Device model loaded successfully.")
    except Exception as e:
        print("Failed to load device model:")
        import traceback
        traceback.print_exc()
        _device_model = None

    try:
        _threat_model = ThreatDetectionModel('threat_model.h5', 'scaler_threat.pkl')
        print("Threat model loaded successfully.")
    except Exception as e:
        print("Failed to load threat model:")
        import traceback
        traceback.print_exc()
        _threat_model = None

# Getter functions for safe access
def get_device_model():
    if _device_model is None:
        initialize_models()
    return _device_model

def get_threat_model():
    if _threat_model is None:
        initialize_models()
    return _threat_model

@model_bp.route('/model')
@login_required
def model_page():
    return render_template('model.html')

@model_bp.route('/model-overview', methods=['GET'])
@login_required
def model_overview():
    try:
        device_latest = MLModel.query.filter(MLModel.parameters.op('@>')(text("'{\"type\": \"device\"}'::jsonb"))).order_by(MLModel.trained_at.desc()).first()
        threat_latest = MLModel.query.filter(MLModel.parameters.op('@>')(text("'{\"type\": \"threat\"}'::jsonb"))).order_by(MLModel.trained_at.desc()).first()

        if not device_latest:
            device_latest = {
                'name': 'DeviceModel_20250902',
                'accuracy': 0.65,
                'training_samples': 200,
                'status': 'trained',
                'trained_at': '2025-09-02T12:00:00'
            }
        else:
            device_latest = device_latest.to_dict()

        if not threat_latest:
            threat_latest = {
                'name': 'ThreatModel_20250902',
                'accuracy': 0.72,
                'training_samples': 200,
                'status': 'trained',
                'trained_at': '2025-09-02T12:00:00'
            }
        else:
            threat_latest = threat_latest.to_dict()

        return jsonify({
            'device': device_latest,
            'threat': threat_latest
        })
    except Exception as e:
        current_app.logger.exception('model_overview failed')
        return jsonify({'error': str(e)}), 500

@model_bp.route('/model/predict', methods=['POST'])
@login_required
def predict_threat():
    data = request.json
    model_type = data.get('model_type')
    if model_type not in ['device', 'threat']:
        return jsonify({'error': 'Invalid model_type. Must be "device" or "threat"'}), 400

    model = get_device_model() if model_type == 'device' else get_threat_model()
    if model is None:
        return jsonify({'error': f'{model_type.capitalize()} model not initialized'}), 500

    required_fields = ['packet_rate', 'byte_rate', 'packet_size', 'protocol_type']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    features = {
        'packet_rate': float(data.get('packet_rate', 0)),
        'byte_rate': float(data.get('byte_rate', 0)),
        'packet_size': float(data.get('packet_size', 0)),
        'protocol_type': float(data.get('protocol_type', 0)),
        'flow_duration': float(data.get('flow_duration', 0)),
        'device_id': data.get('device_id')
    }
    if 'sequence_data' in data:
        features['sequence_data'] = data['sequence_data']

    prediction = model.predict(features, model_type)
    return jsonify({
        'message': f'{model_type.capitalize()} prediction completed',
        **prediction
    })

@model_bp.route('/model/threshold', methods=['POST'])
@login_required
def update_threshold():
    data = request.json
    model_type = data.get('model_type')
    if model_type not in ['device', 'threat']:
        return jsonify({'error': 'Invalid model_type. Must be "device" or "threat"'}), 400

    model = get_device_model() if model_type == 'device' else get_threat_model()
    if model is None:
        return jsonify({'error': f'{model_type.capitalize()} model not initialized'}), 500

    if 'threshold' not in data:
        return jsonify({'error': 'Threshold value required'}), 400

    new_threshold = float(data['threshold'])
    if not 0 <= new_threshold <= 1:
        return jsonify({'error': 'Threshold must be between 0 and 1'}), 400

    model.update_threshold(new_threshold)
    return jsonify({'message': f'{model_type.capitalize()} threshold updated', 'threshold': new_threshold})