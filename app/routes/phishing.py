from flask import Blueprint, render_template, request, session, flash
import os

from app.utils.feature_extractor import FeatureExtractor
from app.utils.history_db import insert_history
from app.utils.model_loader import load_model

phishing_bp = Blueprint("phishing", __name__, template_folder="templates")

# Try to load ML model at import; if missing, we’ll fallback gracefully in the route
try:
    ml_model, feature_names = load_model()
    ML_AVAILABLE = True
except FileNotFoundError as e:
    ml_model, feature_names = None, []
    ML_AVAILABLE = False

@phishing_bp.route("/phishing", methods=["GET", "POST"])
def check_url():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Please enter a URL.")
            return render_template("phishing.html")

        extractor = FeatureExtractor()
        features = extractor.extract_features(url)

        # ---------- Rule-based decision ----------
        is_phishing_rule = (
            features.get("has_brand_impersonation", False)
            or features.get("has_suspicious_tld", False)
            or (features.get("domain_age", 365) >= 0 and features.get("domain_age", 365) < 30)
            or (features.get("has_login_form") and not features.get("has_https"))
        )
        rule_prediction = "Phishing" if is_phishing_rule else "Benign"

        # ---------- ML-based decision ----------
        ml_prediction = "Unavailable"
        ml_prediction_raw = 0
        if ML_AVAILABLE and ml_model is not None and feature_names:
            # Prepare vector in the saved feature order
            feature_vector = [features.get(f, 0) for f in feature_names]
            try:
                ml_prediction_raw = int(ml_model.predict([feature_vector])[0])
                ml_prediction = "Phishing" if ml_prediction_raw == 1 else "Benign"
            except Exception:
                ml_prediction = "Error"

        # ---------- Final decision (OR rule + ML) ----------
        if is_phishing_rule or ml_prediction_raw == 1:
            final_prediction = "Phishing"
        else:
            final_prediction = "Benign"

        # Save history only if requested
        if request.form.get("save_detection") in ["on", "yes", True]:
            user_id = session.get("user_id")
            input_text = f"URL: {url}"
            insert_history(user_id or None, input_text, final_prediction, "Phishing")

        if not ML_AVAILABLE:
            flash("ML model not loaded. Using rule-based detection only. "
                  "Train with: python -m train_models.phishing_train")

        return render_template(
            "phishing_result.html",
            url=url,
            prediction=final_prediction,
            features=features,
            rule_prediction=rule_prediction,
            ml_prediction=ml_prediction,
        )

    return render_template("phishing.html")
