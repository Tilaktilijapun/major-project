# seed_models.py

from app import index  # or from app import create_app if you have a factory
from app.models import MLModel
from app.extensions import db
import uuid
from datetime import datetime

app = index.app  # or create_app()

with app.app_context():
    model1 = MLModel(
        id=str(uuid.uuid4()),
        name="Threat Detection Model",
        model_type="Threat",
        accuracy=91.2,
        status="Trained",
        file_path="ml_models/threat_model.h5",
        created_at=datetime.utcnow()
    )

    model2 = MLModel(
        id=str(uuid.uuid4()),
        name="Device Detection Model",
        model_type="Device",
        accuracy=88.4,
        status="Trained",
        file_path="ml_models/device_model.h5",
        created_at=datetime.utcnow()
    )

    db.session.add_all([model1, model2])
    db.session.commit()
    print("✅ Inserted ML model records successfully.")
