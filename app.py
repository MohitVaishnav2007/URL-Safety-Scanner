import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Define base model class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy with base model
db = SQLAlchemy(model_class=Base)

# Create Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_for_development")

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# VirusTotal API key from environment
app.config['VIRUSTOTAL_API_KEY'] = os.environ.get("VIRUSTOTAL_API_KEY", "")
if not app.config['VIRUSTOTAL_API_KEY']:
    logging.warning("VIRUSTOTAL_API_KEY not set. API functionality will be limited.")

# Initialize the app with the extension
db.init_app(app)

# Create database tables
with app.app_context():
    import models
    db.create_all()
