import os
import sys
import pandas as pd
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Ensure project root is importable when executed as a script
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.append(ROOT)

from app.utils.feature_extractor import FeatureExtractor  # noqa: E402

DATASET_PATH = os.path.join("datasets", "phishing_site_urls.csv")  # must contain: url,label
MODEL_PATH = os.path.join("app", "models", "phishing_xgboost_model.pkl")

# ------------------- TRAINING SCRIPT -------------------

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

print("[INFO] Loading dataset…")
df = pd.read_csv(DATASET_PATH)

if "url" not in df.columns or "label" not in df.columns:
    raise ValueError("Dataset must have columns: 'url', 'label'.")

# Normalize labels to 0/1
label_map = {"phishing": 1, "benign": 0, "malicious": 1, "legit": 0}
y = df["label"].map(lambda v: label_map.get(str(v).strip().lower(), v)).astype(int)

print("[INFO] Extracting features (WHOIS enabled by default; set FEATURE_WHOIS=0 to skip)…")
extractor = FeatureExtractor()

rows = []
for url in df["url"]:
    feats = extractor.extract_features(url)
    rows.append(feats)

X = pd.DataFrame(rows)
feature_names = list(X.columns)

print("[INFO] Train/test split…")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
)

print("[INFO] Training XGBoost…")
model = XGBClassifier(
    n_estimators=300,
    max_depth=7,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=-1,
    eval_metric="logloss",
)
model.fit(X_train, y_train)

print("[INFO] Evaluating…")
y_pred = model.predict(X_test)
print("\nClassification Report:\n", classification_report(y_test, y_pred, digits=4))
print("Accuracy:", f"{accuracy_score(y_test, y_pred):.4f}")

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
joblib.dump((model, feature_names), MODEL_PATH)
print(f"[INFO] Model saved → {MODEL_PATH}")
