import re
from urllib.parse import urlparse
import tldextract
from rapidfuzz import fuzz

# List of major Indian brands targeted by scammers
INDIAN_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "pnb", "paytm", "phonepe", "gpay", 
    "amazon", "flipkart", "irctc", "jio", "airtel", "indiapost", 
    "incometax", "electricity"
]

RISKY_TLDS = {".xyz", ".top", ".click", ".live", ".loan", ".Work", ".cc", ".su", ".gq", ".tk"}

def normalize_homoglyphs(text: str) -> str:
    """Normalize common visual trick replacements (homoglyphs)."""
    text = text.lower()
    # Common replacements
    text = text.replace("rn", "m")
    text = text.replace("0", "o")
    text = text.replace("1", "l")
    text = text.replace("3", "e")
    text = text.replace("vv", "w")
    return text

def analyze_url(url: str) -> dict:
    """Analyze a URL locally for structural risks and brand typosquatting."""
    reasons = []
    risk_score = 0

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    
    subdomain = extracted.subdomain.lower()
    domain = extracted.domain.lower()
    suffix = extracted.suffix.lower()
    full_domain = f"{domain}.{suffix}"
    normalized_full = normalize_homoglyphs(full_domain)

    # 1. Check for HTTPS
    if parsed.scheme != "https":
        risk_score += 15
        reasons.append({"rule": "no_https", "score": 15, "reason": "URL does not use secure HTTPS"})

    # 2. Check for Risky TLDs
    if f".{suffix}" in RISKY_TLDS:
        risk_score += 30
        reasons.append({"rule": "risky_tld", "score": 30, "reason": f"Risky top-level domain (.{suffix}) detected"})

    # 3. IP Address Host Check
    ip_pattern = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(extracted.domain) or ip_pattern.match(parsed.hostname or ""):
        risk_score += 40
        reasons.append({"rule": "ip_host", "score": 40, "reason": "URL uses a raw IP address instead of a domain"})

    # 4. Punycode check (homograph attacks)
    if "xn--" in full_domain:
        risk_score += 35
        reasons.append({"rule": "punycode", "score": 35, "reason": "Punycode (xn--) detected, often used in homograph phishing"})

    # 5. '@' symbol check
    if "@" in url:
        risk_score += 35
        reasons.append({"rule": "@_symbol", "score": 35, "reason": "Contains '@' symbol which can obscure the true destination"})

    # 6. Excessive subdomains or hyphens
    if subdomain.count('.') > 1 or full_domain.count('-') > 2:
        risk_score += 20
        reasons.append({"rule": "excessive_subdomains_hyphens", "score": 20, "reason": "Unusually high number of subdomains or hyphens"})

    # 7. Brand Typosquatting Check against Indian Brands
    for brand in INDIAN_BRANDS:
        # Check if brand is in subdomain or path, but NOT the legitimate registered domain
        in_sub_or_path = brand in subdomain or brand in parsed.path.lower()
        if in_sub_or_path and brand not in domain:
            risk_score += 40
            reasons.append({"rule": "brand_in_subdomain", "score": 40, "reason": f"Brand name '{brand}' found in subdomain/path but not the true domain"})
            break
        
        # Check for fuzzy typosquatting on the domain name itself
        similarity = fuzz.ratio(brand, domain)
        if 75 <= similarity < 100:
            risk_score += 35
            reasons.append({"rule": "typosquatting", "score": 35, "reason": f"Domain looks suspiciously similar to trusted brand '{brand}' (typosquatting)"})
            break

    return {
        "url": url,
        "domain": full_domain,
        "risk_score": min(risk_score, 100),
        "reasons": reasons
    }
