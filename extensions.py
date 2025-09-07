from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy import desc, asc
from sqlalchemy.orm import relationship
from sqlalchemy.sql.expression import text
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)