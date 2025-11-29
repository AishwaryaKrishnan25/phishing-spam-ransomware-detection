import os
import joblib

MODEL_PATH = os.path.join("app", "models", "phishing_xgboost_model.pkl")

def load_model():
    """
    Returns:
        (model, feature_names)

    Raises:
        FileNotFoundError with a clear message if model is missing.
    """
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model file not found at '{MODEL_PATH}'. "
            "Train it first with: python -m train_models.phishing_train"
        )
    return joblib.load(MODEL_PATH)
