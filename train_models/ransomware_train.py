import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import os

# Load dataset
data = pd.read_csv("datasets/ransomware_data.csv")

# Select features and label
X = data[["file_mod_rate", "encrypt_ext_ratio", "proc_spawned", "suspicious_api"]]
y = data["label"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
print("✅ Model Evaluation Report:\n")
print(classification_report(y_test, y_pred))
print("Accuracy:", accuracy_score(y_test, y_pred))

# Save model in app/models/
model_path = os.path.join("app", "models", "ransomware_model.pkl")
joblib.dump(model, model_path)
print(f"✅ Model saved to {model_path}")
