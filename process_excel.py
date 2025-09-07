import pandas as pd
import joblib
from sqlalchemy import create_engine
from models import Device, Threat, DeviceActivityLog, User
from extensions import db
from flask import Flask
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Flask app context for DB
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:kushal07@localhost:5432/aivivid'
db.init_app(app)

# Load scalers
scaler_device = joblib.load('ml_models/scaler_device.pkl')
scaler_threat = joblib.load('ml_models/scaler_threat.pkl')

# Load Excel data
device_df = pd.read_excel('Excel-data/Device Data.xlsx')
threat_df = pd.read_excel('Excel-data/Threat Data.xlsx')

# Columns to use for ML features
ml_columns = ['Anomaly Score']

# Chunk size
chunk_size = 10000

def load_device_data():
    return pd.read_excel('Excel-data/Device Data.xlsx')

def load_threat_data():
    return pd.read_excel('Excel-data/Threat Data.xlsx')


def process_and_save_chunk(df, model_type='threat'):
    if model_type == 'device':
        scaler = scaler_device
        model_class = DeviceActivityLog
        csv_name = 'processed_device_data.csv'
    else:
        scaler = scaler_threat
        model_class = Threat
        csv_name = 'processed_threat_data.csv'

    ml_df = df[['Port', 'Protocol', 'Activity', 'Anomaly Score', 'Threat Detected']].copy()

    for col in ['Protocol', 'Activity', 'Threat Detected']:
        le = LabelEncoder()
        ml_df[col] = le.fit_transform(ml_df[col].astype(str))

    scaled = scaler.transform(ml_df)
    pd.DataFrame(scaled, columns=ml_df.columns).to_csv(csv_name, mode='a', header=False, index=False)

    for _, row in df.iterrows():
        if model_type == 'threat':
            device = db.session.query(Device).filter_by(ip_address=row['IP Address']).first()
            entry_data = {
                'name': f"{row['Activity']} Threat",
                'type': row['Threat Detected'],
                'description': f"Suspicious {row['Activity']} activity detected using {row['Protocol']}.",
                'severity': 'High' if row['Anomaly Score'] > 0.8 else 'Medium',
                'detected_at': row['Timestamp'],
                'status': 'Active',
                'indicator': f"Anomaly Score: {row['Anomaly Score']}",
                'recommended_action': 'Investigate immediately.',
            }
            if device:
                entry_data['affected_device'] = device.id

            entry = model_class(**entry_data)
            db.session.add(entry)

        else:  # model_type == 'device'
            device = db.session.query(Device).filter_by(ip_address=row['IP Address']).first()
            device_id = device.id if device else None
            user_id = device.user_id if device else None  # ✅ This works because user_id is in the Device model

            if user_id is None:
                print(f"⚠️ Skipping row for IP {row['IP Address']} — user_id not found.")
                continue

            entry_data = {
                'user_id': user_id,
                'ip_address': row['IP Address'],
                'protocol': row['Protocol'],
                'activity': row['Activity'],
                'anomaly_score': row['Anomaly Score'],
                'threat_detected': row['Threat Detected'],
                'timestamp': row['Timestamp'],
                'device_id': device_id
            }
            entry = model_class(**entry_data)
            db.session.add(entry)



# Process within app context
with app.app_context():
    # Process Device Data
    for start in range(0, len(device_df), chunk_size):
        chunk = device_df[start:start + chunk_size]
        process_and_save_chunk(chunk, model_type='device')

    # Process Threat Data
    for start in range(0, len(threat_df), chunk_size):
        chunk = threat_df[start:start + chunk_size]
        process_and_save_chunk(chunk, model_type='threat')
