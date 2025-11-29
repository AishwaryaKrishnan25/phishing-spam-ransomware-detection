# ML Security Suite — Phishing, Spam & Ransomware Detection System

## Overview

ML Security Suite is a unified cybersecurity detection platform that identifies and classifies:

- Phishing URLs
- Email Spam
- SMS Spam
- Early Ransomware Behavior

Built using Python + Flask, it combines Machine Learning models and rule-based heuristics to deliver real-time cyber-threat analysis.

---

## Key Features

### User Authentication

- Secure login / registration
- Password hashing
- Full detection history for authenticated users
- Guest users can view limited logs

---

## Threat Detection Modules

### 1. Phishing URL Detection

**Uses:**

- URL lexical analysis
- WHOIS domain age lookup
- Suspicious TLD detection
- HTTPS / SSL validation
- Brand impersonation checks
- XGBoost ML model

---

### 2. Email Spam Detection

**Hybrid ML + Rule Engine:**

- SPF / DKIM / DMARC validation
- Spam keyword detection
- Phishing link extraction
- Multinomial Naïve Bayes + heuristic scoring

---

### 3. SMS Spam Detection

- TF-IDF vectorization
- Text normalization
- Multinomial Naïve Bayes classifier

---

### 4. Ransomware Early Detection

**Behavior-based features:**

- File modification rate
- Encrypted extension ratio
- Process spawn rate
- Suspicious API calls
- Random Forest ML model
- Optional live system scan mode

---

## Dashboard & Reports

- Threat history stored in SQLite
- Filter by Email / SMS / URL / Ransomware
- Guests see last 10 results
- Authenticated users see full analytics

---

## Tech Stack

- Frontend: HTML, CSS, Bootstrap
- Backend: Flask (Python)
- ML Models: XGBoost, RandomForest, Naïve Bayes
- Database: SQLite3
- Libraries: Pandas, NumPy, Scikit-learn, joblib

---

## Installation & Setup

### 1. Clone the Repository

 ```bash
git clone
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate   # Windows
```

### 3. Install Dependencies
 ```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```
App runs at: http://localhost:5000


### Machine Learning Models Used

- Phishing URL → XGBoost

- SMS Spam → Multinomial Naïve Bayes

- Email Spam → Naïve Bayes + Rules

- Ransomware → Random Forest
