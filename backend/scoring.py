def calculate_verdict(total_score: int, in_blocklist: bool = False) -> dict:
    """Determine three-tier verdict and explanation framing."""
    if in_blocklist or total_score >= 70:
        verdict = "Dangerous"
        color = "red"
    elif total_score >= 30:
        verdict = "Suspicious"
        color = "orange"
    else:
        verdict = "No red flags found, verify before acting"
        color = "gray"

    return {
        "score": total_score,
        "verdict": verdict,
        "color": color
    }
