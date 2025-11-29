📌 Overview

ML Security Suite is a unified cybersecurity detection platform that identifies multiple cyber threats using machine learning models and rule-based heuristics.
It provides real-time threat classification for:

Phishing URLs

Email Spam

SMS Spam

Ransomware (Early Detection)

Built using Python + Flask, the system is modular, scalable, and suitable for academic, research, and enterprise learning purposes.

✨ Key Features
🔐 User Authentication

Secure Login/Registration

Password hashing

Full detection history for authenticated users

🧠 Threat Detection Modules
1️⃣ Phishing URL Detection

Uses:

URL lexical analysis

WHOIS domain age lookup

Suspicious TLD detection

HTTPS + URL structure validation

Brand impersonation checks

XGBoost machine learning model

2️⃣ Email Spam Detection

Hybrid system: ML + Rule Engine

SPF, DKIM, DMARC verification

Spam keywords & phishing link detection

Naïve Bayes + heuristic scoring

3️⃣ SMS Spam Detection

TF-IDF vectorization

Text preprocessing

Multinomial Naïve Bayes classifier

4️⃣ Ransomware Early Detection

Based on system behavior:

File modification rate

Encryption extension ratio

Process spawn rate

Suspicious API usage

Random Forest ML model

Optional live system scan mode

📊 Dashboard & Reports

Detection history stored in SQLite

Filter by detection type (Email/SMS/URL/Ransomware)

Guests see last 10 detections

Logged-in users see complete analytics
