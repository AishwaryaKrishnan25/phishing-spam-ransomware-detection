🧩 Overview

ML Security Suite is an integrated cybersecurity detection platform that identifies multiple threat types using machine learning and rule-based analysis.
It provides real-time classification of:

✔️ Phishing URLs
✔️ Email Spam
✔️ SMS Spam
✔️ Ransomware (Early Detection)

The system is designed with modularity, accuracy, and extensibility in mind — ideal for cybersecurity learning, research, and academic projects.

✨ Features
🔐 User Authentication

Secure login & registration

Hashed password storage

Logged-in users get full detection history

🧠 Machine Learning–Powered Detection
1️⃣ Phishing URL Detection

XGBoost ML model

Domain age lookup

Suspicious TLD detection

Brand impersonation checks

HTTPS & URL structure validation

2️⃣ Email Spam Detection

Hybrid: ML + rule engine

SPF, DKIM, DMARC header checks

Phishing link detection

Spam keyword scanning

3️⃣ SMS Spam Detection

Naïve Bayes classifier

TF-IDF feature vectorization

Text normalization & preprocessing

4️⃣ Ransomware Detection

Random Forest classifier

Behavioral features:

file modification rate

encryption extension ratio

process spawn count

suspicious API usage

Live system scanning option

📊 Dashboard & Analytics

Detection history table

Filter by threat category

Shows last 10 detections for anonymous users

Full access for logged-in users

🏗️ Tech Stack
Layer	Tools
Frontend	HTML, CSS, Bootstrap
Backend	Flask (Python)
ML Models	XGBoost, RandomForest, Multinomial Naïve Bayes
Database	SQLite3
Other Libraries	Pandas, NumPy, joblib, re, whois

⚙️ Installation & Setup
1️⃣ Clone the repository
git clone https://github.com/yourusername/yourrepo.git
cd yourrepo

2️⃣ Create & Activate Virtual Environment
python -m venv venv
venv\Scripts\activate       # Windows

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Run Application
python app.py


👉 App starts at: http://localhost:5000

📊 Machine Learning Models Used
Threat Type	Algorithm	Reason
Phishing URL	XGBoost	Best for structured + lexical features
Email Spam	Naïve Bayes + Rules	High precision + context rules
SMS Spam	Multinomial Naïve Bayes	Fast & effective for short texts
Ransomware	Random Forest	Works well with behavior-based features
