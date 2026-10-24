import os
import pickle

try:
    import joblib
except ImportError:
    joblib = None

MODEL_DIR = os.path.join(os.path.dirname(__file__), "../models")
COMBINED_MODEL_PATH = os.path.join(MODEL_DIR, "spam_model.pkl")
TEXT_MODEL_PATH = os.path.join(MODEL_DIR, "sms_spam_model.joblib")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")

_CACHED_MODEL = None
_CACHED_VECTORIZER = None


def _load_file(path: str):
    if joblib is not None:
        return joblib.load(path)
    with open(path, "rb") as f:
        return pickle.load(f)


def load_text_ml_model():
    """Load trained text classifier and vectorizer (cached in memory for fast offline inference)."""
    global _CACHED_MODEL, _CACHED_VECTORIZER
    if _CACHED_MODEL is not None and _CACHED_VECTORIZER is not None:
        return _CACHED_MODEL, _CACHED_VECTORIZER

    # 1. Primary path produced by scripts/train_full_model.py: (vectorizer, clf) tuple in spam_model.pkl
    if os.path.exists(COMBINED_MODEL_PATH):
        try:
            loaded = _load_file(COMBINED_MODEL_PATH)
            if isinstance(loaded, tuple) and len(loaded) == 2:
                _CACHED_VECTORIZER, _CACHED_MODEL = loaded
                return _CACHED_MODEL, _CACHED_VECTORIZER
        except Exception:
            pass

    # 2. Fallback separate joblib files
    if os.path.exists(TEXT_MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        try:
            _CACHED_MODEL = _load_file(TEXT_MODEL_PATH)
            _CACHED_VECTORIZER = _load_file(VECTORIZER_PATH)
            return _CACHED_MODEL, _CACHED_VECTORIZER
        except Exception:
            pass

    return None, None


def predict_text_spam_ml(text: str) -> float:
    """Run offline ML prediction on text. Returns probability score (0.0 to 1.0)."""
    if not text or not text.strip():
        return 0.0

    model, vectorizer = load_text_ml_model()
    if not model or not vectorizer:
        return 0.0  # Fallback if model not trained or sklearn unavailable

    try:
        X = vectorizer.transform([text])
        proba = model.predict_proba(X)[0][1]  # Probability of spam/scam
        return float(proba)
    except Exception:
        return 0.0
