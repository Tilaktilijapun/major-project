from flask import Flask
from extensions import db, limiter  # ✅ Use full path if running from outside app/

from models import User, Device, Alert, Threat, MLModel, ModelTrainingHistory  # ✅ Import all models to register them

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:kushal07@localhost:5432/aivivid'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)  # ✅ Proper initialization
    limiter.init_app(app)  # ✅ Initialize limiter

    # Register blueprints
    from .user_dashboard import user_dashboard_bp
    app.register_blueprint(user_dashboard_bp)
    
    # Blueprint registration
    from app.admin.admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/admin')

    with app.app_context():
        db.create_all()

    return app
