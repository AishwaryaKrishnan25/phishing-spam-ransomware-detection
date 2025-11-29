# sms_train.py (Multinomial Naive Bayes Version)

import pandas as pd
import joblib
import os
import re
import string
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report

# --- Preprocessing Function ---
def preprocess_text(text):
    text = text.lower()
    text = re.sub(r'\d+', '', text)  # remove digits
    text = re.sub(r'https?://\S+|www\.\S+', '', text)  # remove URLs
    text = re.sub(r'<.*?>', '', text)  # remove HTML tags
    text = text.translate(str.maketrans('', '', string.punctuation))  # remove punctuation
    text = re.sub(r'\s+', ' ', text).strip()  # remove extra spaces
    return text

# --- Load & Clean Dataset ---
df = pd.read_csv('datasets/sms_spam.csv', encoding='latin-1')
df = df[['v1', 'v2']]
df.columns = ['label', 'message']
df['label'] = df['label'].map({'ham': 0, 'spam': 1})
df['message'] = df['message'].apply(preprocess_text)

# --- Train/Test Split ---
X_train, X_test, y_train, y_test = train_test_split(
    df['message'], df['label'], test_size=0.2, random_state=42
)

# --- Model Pipeline ---
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        stop_words='english',
        ngram_range=(1, 2),
        max_df=0.9,
        min_df=5
    )),
    ('clf', MultinomialNB())
])

# --- Train Model ---
pipeline.fit(X_train, y_train)

# --- Evaluate Model ---
y_pred = pipeline.predict(X_test)
print(classification_report(y_test, y_pred))

# --- Save Model ---
os.makedirs('app/models', exist_ok=True)
joblib.dump(pipeline, 'app/models/sms_model.pkl')

print("✅ SMS spam model trained using Multinomial Naive Bayes and saved as sms_model.pkl")
