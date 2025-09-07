from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_login import LoginManager, login_user, current_user
from flask_socketio import SocketIO
from flask_migrate import Migrate
from extensions import db, func  # ✅ Use the central db instance
from models import User, Device, Threat, Alert, NotificationPreference, PricingPlans, demo, Subscription, ThreatDetails

# Import blueprints
from admin.admin import admin_bp
from demo import demo_bp
from auth import auth_bp
from contactus import contactus_bp
from aboutus import aboutus_bp
from user_dashboard import user_dashboard_bp
from user import user as user_bp
from security_scan import security_scan_bp
from pricing import pricing_bp
from monitoring import init_monitoring, monitoring_bp
from user_profile import user_profile_bp
from chatbot import chatbot_bp
from settings import settings_bp
from user_activity import user_activity_bp
from data_dashboard import data_dashboard_bp
from admin.admin_dashboard import admin_dashboard_bp
from admin.threats_management import threats_management_bp
from admin.setting import setting_bp
from admin.user_management import user_management_bp
from admin.reports import reports_bp
from admin.analytics import analytics_bp
from admin.ml_model import ml_model_bp
from admin.admin_profile import admin_profile_bp
from security_alerts import alerts_bp
from security_recommendations import security_recommendations_bp
from ml_features import ml_features_bp
from threat_details import threat_bp
from model import model_bp
from blog import blog_bp
from flask_cors import CORS


# Initialize app
app = Flask(__name__,
            template_folder='../templates',
            static_folder='../static',
            static_url_path='/static')

CORS(app)  # Allow all origins (restrict in production)

# Load configuration
import config
app.config.from_object(config)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

@login_manager.unauthorized_handler
def unauthorized_callback():
    return jsonify({"error": "User not logged in"}), 401

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


# Register all blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(user_dashboard_bp, url_prefix='/user/dashboard')
app.register_blueprint(contactus_bp, url_prefix='/contact')
app.register_blueprint(aboutus_bp, url_prefix='/about')
app.register_blueprint(user_bp, url_prefix='/user')
app.register_blueprint(demo_bp, url_prefix='/demo')
app.register_blueprint(pricing_bp, url_prefix='/pricing')
app.register_blueprint(security_scan_bp, url_prefix='/user/security_scan')
app.register_blueprint(alerts_bp, url_prefix='/user/security_alerts')
app.register_blueprint(security_recommendations_bp, url_prefix='/user/security_recommendations')
app.register_blueprint(threat_bp, url_prefix='/user/threat_details')
app.register_blueprint(ml_features_bp, url_prefix='/user/ml_features')
app.register_blueprint(model_bp, url_prefix='/user/model')
app.register_blueprint(blog_bp, url_prefix='/user/blog')
app.register_blueprint(monitoring_bp, url_prefix='/monitoring')
app.register_blueprint(user_profile_bp, url_prefix='/user/profile')
app.register_blueprint(chatbot_bp, url_prefix='/chatbot')
app.register_blueprint(settings_bp, url_prefix='/settings')
app.register_blueprint(user_activity_bp, url_prefix='/user/activity')
app.register_blueprint(data_dashboard_bp, url_prefix='/data_dashboard')
app.register_blueprint(admin_dashboard_bp, url_prefix='/admin/dashboard')
app.register_blueprint(threats_management_bp, url_prefix='/admin/threats-management')
app.register_blueprint(reports_bp, url_prefix='/admin/reports')
app.register_blueprint(analytics_bp, url_prefix='/admin/analytics')
app.register_blueprint(ml_model_bp, url_prefix='/admin/ml-model')
app.register_blueprint(user_management_bp, url_prefix='/admin/user-management')
app.register_blueprint(setting_bp, url_prefix='/admin/setting')
app.register_blueprint(admin_profile_bp, url_prefix='/admin/profile')

# Inject current user globally in templates
@app.context_processor
def inject_user():
    return dict(user=current_user)

@app.route('/', endpoint='index')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('index.html')

@app.route('/pricing')
def pricing():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    plans = PricingPlans.query.all()
    return render_template('pricing.html', plans=plans)

@app.route('/about')
def about():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('aboutus.html')

@app.route('/contact')
def contact():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('contactus.html')

@app.route('/demo')
def demo():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return render_template('demo.html')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Run the app
socketio = SocketIO(app, cors_allowed_origins="*")
init_monitoring(app, socketio)

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully!")
        except Exception as e:
            print(f"Error creating database tables: {e}")
            import traceback
            traceback.print_exc()

    try:
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)
    except Exception as e:
        print(f"Error starting the server: {e}")
        import traceback
        traceback.print_exc()
