def calculate_verdict(total_score: int, in_blocklist: bool = False) -> dict:
    """Determine three-tier verdict: Dangerous / Suspicious / No red flags."""
    if in_blocklist or total_score >= 70:
        verdict = "Dangerous"
        color = "red"
        explanation = "High risk of scam or financial fraud. Do not interact or click."
    elif total_score >= 30:
        verdict = "Suspicious"
        color = "orange"
        explanation = "Potential warning signs detected. Proceed with extreme caution."
    else:
        verdict = "No red flags found, verify before acting"
        color = "gray"
        explanation = "No known scam patterns matched, but always independently verify."

    return {
        "score": min(total_score, 100),
        "verdict": verdict,
        "color": color,
        "default_advice": explanation
    }
