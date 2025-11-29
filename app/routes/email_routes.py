import pickle
from flask import Blueprint, request, render_template, session
from datetime import datetime
from app.utils.email_features import *
from app.utils.history_db import insert_history

email_bp = Blueprint('email', __name__)

# ------------------------------
# Load model + vectorizer
# ------------------------------
with open('app/models/email_spam_model.pkl', 'rb') as f:
    data = pickle.load(f)
    model = data['model']
    vectorizer = data['vectorizer']

# ------------------------------
# Rule weights (rebalanced)
# ------------------------------
rule_weights = {
    'suspicious_domain': 2.0,
    'spam_keywords': 1.0,
    'phishing_url': 1.5,        # REDUCED from 3.0
    'malicious_attachment': 4.0,
    'spf_fail': 1.0,
    'dkim_fail': 1.0,
    'dmarc_fail': 0.5,
    'typo_domain': 1.5          # REDUCED
}

blacklist = load_blacklist()

SAFE_DOMAINS = [
    'amazon.in', 'amazon.com', 'google.com', 'gmail.com', 'annauniv.edu',
    'outlook.com', 'office.com', 'microsoft.com', 'paypal.com'
]

# ------------------------------
# Rule scoring function
# ------------------------------
def rule_score(features):
    score = 0

    if features['is_suspicious_domain']:
        score += rule_weights['suspicious_domain']

    if features['is_typo_domain']:
        score += rule_weights['typo_domain']

    score += rule_weights['spam_keywords'] * len(features['spam_keywords'])

    # Ignore "None detected" phishing URLs
    phishing_urls = [p for p in features['phishing_urls'] if p != "None detected"]
    score += rule_weights['phishing_url'] * len(phishing_urls)

    malicious_attachments = [
        m for m in features['malicious_attachments'] if m != "None detected"
    ]
    score += rule_weights['malicious_attachment'] * len(malicious_attachments)

    if features['spf_status'] != 'pass':
        score += rule_weights['spf_fail']

    if features['dkim_status'] != 'pass':
        score += rule_weights['dkim_fail']

    if features['dmarc_status'] != 'pass':
        score += rule_weights['dmarc_fail']

    return score

# ------------------------------
# Main Email Check Route
# ------------------------------
@email_bp.route('/email', methods=['GET', 'POST'])
def check_email():

    if request.method == 'POST':

        sender = request.form.get('from', '')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        spf_status = request.form.get('spf', 'none').lower()
        dkim_status = request.form.get('dkim', 'none').lower()
        dmarc_status = request.form.get('dmarc', 'none').lower()
        x_origin_ip = request.form.get('x_origin', '')

        attachments_raw = request.form.get('attachments', '')
        attachments = [x.strip() for x in attachments_raw.split(',') if x.strip()]

        sender_domain = extract_domain(sender)

        phishing_urls = detect_phishing_urls(body, blacklist['domains'])
        phishing_urls = phishing_urls if phishing_urls else ["None detected"]

        malicious_attachments = check_malicious_attachments(
            [{'filename': att} for att in attachments]
        )
        malicious_attachments = malicious_attachments if malicious_attachments else ["None detected"]

        # Feature Collection
        features = {
            'sender': sender,
            'subject': subject,
            'body': body,
            'sender_domain': sender_domain,
            'x_origin_ip': x_origin_ip,
            'attachments': attachments,
            'is_suspicious_domain': sender_domain in blacklist['domains'],
            'is_typo_domain': any(is_typo(sender_domain, legit) for legit in SAFE_DOMAINS),
            'spam_keywords': detect_spam_keywords(subject + ' ' + body),
            'phishing_urls': phishing_urls,
            'malicious_attachments': malicious_attachments,
            'spf_status': spf_status,
            'dkim_status': dkim_status,
            'dmarc_status': dmarc_status
        }

        # ------------------------------
        # Hybrid Score
        # ------------------------------
        rule = rule_score(features)

        ml_input = subject + " " + body + " " + sender_domain
        ml_vec = vectorizer.transform([ml_input])
        ml_prob = model.predict_proba(ml_vec)[0][1] * 10

        final_score = 0.85 * rule + 0.15 * ml_prob  # ML weight reduced

        # ------------------------------
        # Classification Threshold
        # ------------------------------
        if final_score >= 7:
            label = "SPAM"
        elif final_score <= 4.5:
            label = "HAM"
        else:
            label = "SUSPICIOUS"

        # ------------------------------
        # SAFE DOMAIN OVERRIDE (fix false positives)
        # ------------------------------
        if sender_domain in SAFE_DOMAINS:
            label = "HAM"
            final_score = 0.0

        # ------------------------------
        # Save history
        # ------------------------------
        if request.form.get('save_request') in ['on', 'yes', True]:
            user_id = session.get('user_id')
            input_text = f"From: {sender}, Subject: {subject}"
            insert_history(user_id or None, input_text, label, "Email")

        return render_template("email_result.html",
                               label=label,
                               score=round(final_score, 2),
                               features=features)

    return render_template('email.html')
