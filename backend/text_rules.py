import re

SCAM_PATTERNS = {
    "kyc_expiry": {
        "keywords": ["kyc", "expire", "block", "pan card", "update", "suspended", "dear customer your kyc"],
        "hindi_hinglish": ["kyc band", "khata band", "block ho jayega", "update karo", "kyc expire"],
        "score": 35,
        "description": "Fake KYC expiry / account block threat"
    },
    "electricity_disconnection": {
        "keywords": ["electricity", "power", "bill", "disconnect", "mseb", "cesc", "bses", "night", "cutoff"],
        "hindi_hinglish": ["bijli kaat", "power cut", "light kategi", "bill baki", "payment nahi kiya"],
        "score": 35,
        "description": "Fake electricity bill disconnection threat"
    },
    "digital_arrest": {
        "keywords": ["cbi", "cyber cell", "arrest", "court", "supreme court", "video call", "mumbai police", "narcotics", "illegal parcel"],
        "hindi_hinglish": ["girftar", "police case", "video call par aao", "cbi inquiry", "court warrant"],
        "score": 50,
        "description": "Digital arrest / fake law enforcement intimidation scam"
    },
    "fake_job_wfh": {
        "keywords": ["part time", "work from home", "youtube", "task", "telegram", "daily income", "investment", "earn money"],
        "hindi_hinglish": ["ghar baithe", "part time job", "paisa kamao", "telegram group join"],
        "score": 30,
        "description": "Fake job / task-based earning scam"
    },
    "lottery_prize": {
        "keywords": ["lottery", "won", "congratulations", "lucky draw", "kbc", "prize", "crore", "lakh"],
        "hindi_hinglish": ["jeeta hai", "inaam", "kbc lottery", "congrats lucky draw"],
        "score": 35,
        "description": "Lottery / prize winner scam"
    },
    "upi_collect_refund": {
        "keywords": ["refund", "cashback", "collect request", "approve", "pin enter", "receive money"],
        "hindi_hinglish": ["paisa paane ke liye", "upi pin dalo", "refund milega", "collect request accept"],
        "score": 40,
        "description": "UPI collect request trick (money deduction scam)"
    },
    "parcel_customs": {
        "keywords": ["fedex", "customs", "illegal items", "drugs", "parcel seized", "holding package"],
        "hindi_hinglish": ["parcel pakda gaya", "customs duty", "illegal courier"],
        "score": 40,
        "description": "Customs / seized parcel scam"
    },
    "loan_app": {
        "keywords": ["instant loan", "low interest", "no cibil", "bad cibil", "disbursed"],
        "hindi_hinglish": ["turant loan", "aadhar par loan", " bina cibil loan"],
        "score": 30,
        "description": "Predatory / fake instant loan app scam"
    },
    "apk_install": {
        "keywords": [".apk", "download app", "install apk", "update app link", "sanchar saathi apk"],
        "hindi_hinglish": ["apk download", "app install karo", "link se app"],
        "score": 45,
        "description": "Malicious APK installation prompt"
    }
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 2 hours", "today itself", "last chance", 
    "turant", "abhi karo", "last date", "jaldi", "warning", "final notice"
]

def analyze_message_text(text: str) -> dict:
    """Analyze message text for scam categories and pressure phrases."""
    text_lower = text.lower()
    reasons = []
    rule_score = 0
    matched_categories = []

    # 1. Check scam patterns
    for cat_key, cat_data in SCAM_PATTERNS.items():
        all_terms = cat_data["keywords"] + cat_data["hindi_hinglish"]
        if any(term in text_lower for term in all_terms):
            rule_score += cat_data["score"]
            matched_categories.append(cat_key)
            reasons.append({
                "rule": f"text_pattern_{cat_key}",
                "score": cat_data["score"],
                "reason": cat_data["description"]
            })

    # 2. Check urgency / pressure phrases
    urgency_found = any(urg in text_lower for urg in URGENCY_KEYWORDS)
    if urgency_found:
        rule_score += 15
        reasons.append({
            "rule": "urgency_pressure",
            "score": 15,
            "reason": "High-urgency pressure language detected (forcing hasty action)"
        })

    return {
        "rule_score": min(rule_score, 100),
        "categories": matched_categories,
        "urgency_detected": urgency_found,
        "reasons": reasons
    }
