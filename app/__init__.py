from flask import Flask
from app.routes.sms import sms_bp
from app.routes.phishing import phishing_bp
from app.routes.email_routes import email_bp
from app.routes.ransomware import ransomware_bp
from app.routes.auth import auth_bp
from app.routes.home import home_bp
from app.routes.dashboard import dashboard_bp
from app.utils.history_db import init_history_table

def create_app():
    app = Flask(__name__)
    app.secret_key = 'your-secret-key'

    init_history_table()
    app.register_blueprint(home_bp)
    app.register_blueprint(sms_bp)
    app.register_blueprint(phishing_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(ransomware_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp) 

    return app
