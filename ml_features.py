from flask import Blueprint, jsonify, request, render_template
from models import db, MLManager, Prediction, Device
from datetime import datetime
import tensorflow as tf
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
import os
from flask_login import login_required, current_user
from extensions import db

ml_features_bp = Blueprint('ml_features', __name__)

@ml_features_bp.route('/ml_features')
@login_required
def ml_features_page():
    return render_template('ml-features.html')

# Path to save the model
MODEL_PATH = "saved_model/my_model"

# Generate dummy training data
def generate_data():
    # Input: 100 samples, each with 10 features
    x_train = np.random.rand(100, 10)
    # Output: binary labels (0 or 1)
    y_train = np.random.randint(0, 2, 100)
    return x_train, y_train

# Train and save the model
def train_model():
    x_train, y_train = generate_data()

    model = Sequential([
        Dense(64, activation='relu', input_shape=(10,)),
        Dense(32, activation='relu'),
        Dense(1, activation='sigmoid')  # Binary classification
    ])

    model.compile(optimizer='adam',
                  loss='binary_crossentropy',
                  metrics=['accuracy'])

    print("[INFO] Training model...")
    model.fit(x_train, y_train, epochs=5, batch_size=8)

    # Save the model
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    model.save(MODEL_PATH)
    print(f"[INFO] Model saved at {MODEL_PATH}")

# Load model and make a prediction
def predict_new_data(input_array):
    if not os.path.exists(MODEL_PATH):
        print("[ERROR] Model not found. Please train first.")
        return None

    model = tf.keras.models.load_model(MODEL_PATH)

    # Ensure input is numpy array with correct shape
    input_array = np.array(input_array).reshape(1, 10)

    prediction = model.predict(input_array)
    return float(prediction[0][0])

# Threat level classification
def predict_threat_level(features):
    """
    Accepts a list of 10 numeric features and returns a threat level.
    """
    probability = predict_new_data(features)

    if probability is None:
        return "Model not available"

    if probability < 0.33:
        return "Low"
    elif probability < 0.66:
        return "Medium"
    else:
        return "High"

# Optional API endpoint for predictions
@ml_features_bp.route('/api/predict-threat', methods=['POST'])
def api_predict_threat():
    data = request.json.get('features')
    if not data or len(data) != 10:
        return jsonify({"error": "Please provide a list of 10 numerical features."}), 400

    threat_level = predict_threat_level(data)
    return jsonify({"threat_level": threat_level})

# Run this file directly to train and test
if __name__ == "__main__":
    train_model()

    example_input = np.random.rand(10)  # 10 features
    result = predict_new_data(example_input)
    print(f"[PREDICTION] Probability: {result:.4f}")

    level = predict_threat_level(example_input)
    print(f"[THREAT LEVEL] {level}")

# Analyze multiple threat patterns
def analyze_threat_pattern(feature_list):
    """
    Accepts a list of feature sets (each with 10 features),
    returns a list of threat level classifications.
    """
    if not os.path.exists(MODEL_PATH):
        print("[ERROR] Model not found. Please train first.")
        return ["Model not available"]

    model = tf.keras.models.load_model(MODEL_PATH)

    try:
        input_array = np.array(feature_list)
        if input_array.ndim != 2 or input_array.shape[1] != 10:
            raise ValueError("Each feature set must contain exactly 10 numeric features.")

        predictions = model.predict(input_array)
        results = []

        for prob in predictions:
            p = prob[0]
            if p < 0.33:
                results.append("Low")
            elif p < 0.66:
                results.append("Medium")
            else:
                results.append("High")

        return results

    except Exception as e:
        print(f"[ERROR] {e}")
        return ["Invalid input format"]

# Optional batch API endpoint
@ml_features_bp.route('/api/analyze-threats', methods=['POST'])
def api_analyze_threats():
    data = request.json.get('feature_sets')
    if not data or not isinstance(data, list) or any(len(f) != 10 for f in data):
        return jsonify({"error": "Please provide a list of feature sets, each with 10 numerical features."}), 400

    threat_levels = analyze_threat_pattern(data)
    return jsonify({"results": threat_levels})
