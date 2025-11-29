from flask import Blueprint, render_template, request, session
import joblib, os, sqlite3
from app.utils.decorator import login_required
from app.utils.history_db import DB_PATH

sms_bp = Blueprint('sms', __name__)
sms_model = joblib.load(os.path.join('app', 'models', 'sms_model.pkl'))

@sms_bp.route('/sms-spam', methods=['GET', 'POST'])
@login_required
def sms_spam():
    if request.method == 'POST':
        message = request.form.get('message', '')
        pred_result = int(sms_model.predict([message])[0])
        prediction = "Scam" if pred_result == 1 else "Original"

        # ✅ Save to history only if checkbox is checked
        if request.form.get('save_request') in ['on', 'yes', True]:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO history (user_id, input_text, prediction, model_type)
                    VALUES (?, ?, ?, ?)
                ''', (session.get('user_id'), message, prediction, 'SMS'))
                conn.commit()
            except Exception as e:
                print(f"[DB ERROR] Failed to insert SMS history: {e}")
            finally:
                conn.close()

        return render_template('sms_result.html', message=message, prediction=prediction)

    return render_template('sms.html')
