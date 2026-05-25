import re
import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import numpy as np

# ── Built-in training data ────────────────────────────────
# Real projects use datasets like CEAS/Enron. We use a
# representative built-in set so it works with zero setup.

PHISHING_SAMPLES = [
    "urgent your account has been suspended verify your identity immediately click here",
    "dear customer your paypal account will be closed enter your password now",
    "congratulations you have won a cash reward claim your prize today",
    "your account shows unusual activity confirm your details or face suspension",
    "security alert unauthorized access detected login to verify your account",
    "final notice your bank account will be terminated provide your banking details",
    "dear valued customer update your information immediately to avoid account closure",
    "you have been selected for an exclusive offer enter your credit card details",
    "your ip has been logged suspicious activity verify your identity now",
    "act now your account expires in 24 hours enter your social security number",
    "dear user legal action will be taken failure to respond immediately",
    "click here to reactivate your account submit your payment information",
    "greetings from security team your password must be reset immediately",
    "limited time offer claim your free gift provide your personal details",
    "your account will be deleted unless you verify your details within 48 hours",
    "warning unauthorized login attempt confirm your password to secure account",
    "dear account holder your credit card has been compromised update now",
    "you are selected as lucky winner enter your details to claim reward",
    "helpdesk notice your email account storage is full verify immediately",
    "official notice from support team your account needs immediate verification",
]

LEGITIMATE_SAMPLES = [
    "hi team the meeting is scheduled for tuesday at 3pm please confirm attendance",
    "attached is the quarterly report for your review let me know if you have questions",
    "thank you for your order your package will arrive within 3 to 5 business days",
    "reminder your subscription renews on the 15th no action required",
    "your receipt for recent purchase is attached please keep for your records",
    "weekly newsletter top stories in technology and business this week",
    "your flight booking confirmation details are attached have a great trip",
    "project update we have completed the first milestone ahead of schedule",
    "invitation you are invited to our annual company picnic on friday",
    "your password was successfully changed if you did not do this contact support",
    "hi the client presentation went well they are interested in moving forward",
    "monthly statement your account balance is available in the portal",
    "thank you for contacting support we will respond within one business day",
    "your appointment is confirmed for thursday at 10am see you then",
    "new message from your colleague please review the attached document",
    "course completion certificate attached congratulations on finishing the course",
    "your github pull request has been reviewed and approved merge when ready",
    "team lunch is on friday at noon at the usual place hope to see everyone",
    "your annual tax documents are ready to download from the portal",
    "good morning here is your daily briefing for today no urgent items",
]

MODEL_PATH = "modules/phish_model.pkl"


def _build_training_data():
    texts  = PHISHING_SAMPLES + LEGITIMATE_SAMPLES
    labels = [1] * len(PHISHING_SAMPLES) + [0] * len(LEGITIMATE_SAMPLES)
    return texts, labels


def train_model():
    """
    Trains a TF-IDF + Logistic Regression pipeline.
    Saves the model to disk for reuse.
    """
    texts, labels = _build_training_data()

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),   # unigrams + bigrams
            max_features=500,     # top 500 features
            sublinear_tf=True,    # log normalization
            stop_words="english"
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            C=1.0,
            solver="lbfgs"
        ))
    ])

    pipeline.fit(texts, labels)

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)

    print("✅ [ML Classifier] Model trained and saved")
    return pipeline


def load_or_train_model():
    """
    Loads saved model if exists, otherwise trains a new one.
    """
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    return train_model()


def classify_email(parsed_email) -> dict:
    """
    Main function — takes parsed email, runs TF-IDF + LR classifier.
    Returns risk score (0-40), label, and confidence.
    """
    # Get body text for classification
    body = parsed_email.get("body_text", "")
    if not body:
        from bs4 import BeautifulSoup
        html = parsed_email.get("body_html", "")
        body = BeautifulSoup(html, "html.parser").get_text(separator=" ") if html else ""

    subject = parsed_email.get("subject", "")
    text    = f"{subject} {body}".strip()

    if not text:
        return {
            "ml_label":      "UNKNOWN",
            "ml_confidence": 0.0,
            "risk_score":    0,
            "risk_flags":    []
        }

    model      = load_or_train_model()
    proba      = model.predict_proba([text])[0]
    phish_prob = float(proba[1])   # probability of being phishing
    label      = "PHISHING" if phish_prob >= 0.5 else "LEGITIMATE"

    # Convert probability to risk score (0-40 range)
    # so it integrates cleanly with your existing scoring system
    risk_score = int(phish_prob * 40)

    risk_flags = []
    if phish_prob >= 0.5:
        risk_flags.append({
            "code":    "ML_PHISHING_DETECTED",
            "message": f"TF-IDF + Logistic Regression classifier flagged email as phishing (confidence: {phish_prob:.0%})",
            "score":   risk_score
        })

    return {
        "ml_label":      label,
        "ml_confidence": round(phish_prob, 3),
        "risk_score":    risk_score,
        "risk_flags":    risk_flags
    }