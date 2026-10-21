import os
import joblib

MODEL_DIR = os.path.join(os.path.dirname(__file__), "../models")
TEXT_MODEL_PATH = os.path.join(MODEL_DIR, "sms_spam_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")

def load_text_ml_model():
    """Load trained text classifier and vectorizer if available."""
    if os.path.exists(TEXT_MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        try:
            model = joblib.load(TEXT_MODEL_PATH)
            vectorizer = joblib.load(VECTORIZER_PATH)
            return model, vectorizer
        except Exception:
            pass
    return None, None

def predict_text_spam_ml(text: str) -> float:
    """Run ML prediction on text. Returns probability score (0.0 to 1.0)."""
    model, vectorizer = load_text_ml_model()
    if not model or not vectorizer:
        return 0.0  # Fallback if model not trained yet
    
    try:
        X = vectorizer.transform([text])
        proba = model.predict_proba(X)[0][1] # Probability of spam/scam
        return float(proba)
    except Exception:
        return 0.0
