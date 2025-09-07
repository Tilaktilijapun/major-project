from datetime import timedelta

# Database Configuration
SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:kushal07@localhost:5432/aivivid'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Application Configuration
SECRET_KEY = '007'  # Change this to a secure value in production
DEBUG = True  # Set to False in production

# Session Configuration
PERMANENT_SESSION_LIFETIME = timedelta(days=7)
SESSION_COOKIE_SECURE = False  # Set to True if using HTTPS
SESSION_COOKIE_HTTPONLY = True

# Security Configuration
WTF_CSRF_ENABLED = True
WTF_CSRF_SECRET_KEY = 'your-csrf-secret-key'  # Change this to a secure value

# Upload Configuration
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# API Configuration
JSON_SORT_KEYS = False
JSONIFY_PRETTYPRINT_REGULAR = False

# Pagination Configuration
PER_PAGE = 10

# Logging Configuration
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = 'INFO'