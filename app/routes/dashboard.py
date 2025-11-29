from flask import Blueprint, render_template, request, session, redirect, url_for
import sqlite3
from app.utils.history_db import DB_PATH

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
def dashboard():
    model_filter = request.args.get('filter')
    see_all = request.args.get('see_all') == 'true'
    is_logged_in = 'user_id' in session

    # Determine data limit
    data_limit = None if is_logged_in and see_all else 10

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Model count queries
    c.execute("SELECT COUNT(*) FROM history WHERE model_type='SMS'")
    sms_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM history WHERE model_type='Phishing'")
    phishing_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM history WHERE model_type='Email'")
    email_count = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM history WHERE model_type='Ransomware'")
    ransomware_count = c.fetchone()[0]

    # Data fetching
    query = """
        SELECT input_text, prediction, model_type, timestamp
        FROM history
    """
    params = []

    if model_filter and model_filter in ['SMS', 'Phishing', 'Email', 'Ransomware']:
        query += " WHERE model_type = ?"
        params.append(model_filter)

    query += " ORDER BY timestamp DESC"
    if data_limit:
        query += " LIMIT ?"
        params.append(data_limit)

    c.execute(query, tuple(params))
    recent_detections = c.fetchall()
    conn.close()

    return render_template(
        'dashboard.html',
        sms_count=sms_count,
        phishing_count=phishing_count,
        email_count=email_count,
        ransomware_count=ransomware_count,
        recent_detections=recent_detections,
        selected_filter=model_filter,
        is_logged_in=is_logged_in,
        showing_all=(see_all and is_logged_in)
    )
