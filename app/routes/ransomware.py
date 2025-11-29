import os
import json
import numpy as np
import joblib
import sqlite3
from flask import Blueprint, request, render_template, session
from app.utils.decorator import login_required
from app.utils.history_db import DB_PATH
from app.utils.generate_ransomware_features import generate_features_from_system

ransomware_bp = Blueprint('ransomware', __name__)

# Load the ransomware detection model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "../models/ransomware_model.pkl")
model = joblib.load(MODEL_PATH)

@ransomware_bp.route('/ransomware', methods=['GET'], strict_slashes=False)
@login_required
def ransomware_upload():
    return render_template("ransomware.html")


@ransomware_bp.route('/ransomware/result', methods=['POST'], strict_slashes=False)
@login_required
def ransomware_result():
    result = None
    message = None
    prediction = "Error"
    features = {}

    file = request.files.get('feature_file')
    if not file or not file.filename.endswith('.json'):
        result = "❌ Please upload a valid .json file."
        return render_template("ransomware_result.html", result=result, features={}, scanned_path=None)

    try:
        features = json.load(file)
        input_data = np.array([[ 
            features.get("file_mod_rate", 0),
            features.get("encrypt_ext_ratio", 0),
            features.get("proc_spawned", 0),
            features.get("suspicious_api", 0)
        ]])

        pred_result = int(model.predict(input_data)[0])
        prediction = "Ransomware" if pred_result == 1 else "Safe"
        result = "🚨 Ransomware Detected!" if pred_result == 1 else "✅ System is Safe"

        message = (
            f"File Modification Rate: {features.get('file_mod_rate', 0)}, "
            f"Encryption Extension Ratio: {features.get('encrypt_ext_ratio', 0)}, "
            f"Processes Spawned: {features.get('proc_spawned', 0)}, "
            f"Suspicious API Usage: {features.get('suspicious_api', 0)}"
        )

        save_request = request.form.get('save_request')
        if save_request in ['on', 'yes', True]:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                INSERT INTO history (user_id, input_text, prediction, model_type)
                VALUES (?, ?, ?, ?)
            ''', (
                session['user_id'],
                message,
                prediction,
                'Ransomware'
            ))
            conn.commit()
            conn.close()

    except Exception as e:
        result = f"❌ Error during detection: {str(e)}"
        features = {}

    return render_template("ransomware_result.html", result=result, features=features)


@ransomware_bp.route('/ransomware/system-check', methods=['POST'], strict_slashes=False)
@login_required
def ransomware_generate():
    result = None
    message = None
    prediction = "Error"
    features = {} 
    scanned_path = "Unknown"

    try:
        output = generate_features_from_system()
        features = output.get("features", {})
        scanned_path = output.get("path", "Unknown")

        input_data = np.array([[ 
            features.get("file_mod_rate", 0),
            features.get("encrypt_ext_ratio", 0),
            features.get("proc_spawned", 0),
            features.get("suspicious_api", 0)
        ]])

        pred_result = int(model.predict(input_data)[0])
        prediction = "Ransomware" if pred_result == 1 else "Safe"
        result = "🚨 Ransomware Detected!" if pred_result == 1 else "✅ System is Safe"

        message = (
            f"File Modification Rate: {features.get('file_mod_rate', 0)}, "
            f"Encryption Extension Ratio: {features.get('encrypt_ext_ratio', 0)}, "
            f"Processes Spawned: {features.get('proc_spawned', 0)}, "
            f"Suspicious API Usage: {features.get('suspicious_api', 0)}"
        )

        save_request = request.form.get('save_request')
        if save_request in ['on', 'yes', True]:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                INSERT INTO history (user_id, input_text, prediction, model_type)
                VALUES (?, ?, ?, ?)
            ''', (
                session['user_id'],
                message,
                prediction,
                'Ransomware'
            ))
            conn.commit()
            conn.close()

    except Exception as e:
        result = f"❌ Error during auto-analysis: {str(e)}"
        features = {}
        scanned_path = scanned_path

    return render_template("ransomware_result.html", result=result, features=features, scanned_path=scanned_path)
