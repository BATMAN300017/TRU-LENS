import re
from urllib.parse import urlparse
from difflib import SequenceMatcher

# Use offline Public Suffix List snapshot if tldextract is installed; otherwise pure-Python fallback
try:
    import tldextract
    _OFFLINE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
except ImportError:
    _OFFLINE_EXTRACTOR = None

try:
    from rapidfuzz import fuzz
    def _similarity_ratio(a: str, b: str) -> float:
        return float(fuzz.ratio(a, b))
except ImportError:
    def _similarity_ratio(a: str, b: str) -> float:
        return SequenceMatcher(None, a, b).ratio() * 100.0

# List of major Indian brands targeted by scammers
INDIAN_BRANDS = [
    "sbi", "hdfc", "icici", "axis", "pnb", "paytm", "phonepe", "gpay",
    "amazon", "flipkart", "irctc", "jio", "airtel", "indiapost",
    "incometax", "electricity"
]

RISKY_TLDS = {".xyz", ".top", ".click", ".live", ".loan", ".work", ".cc", ".su", ".gq", ".tk", ".buzz", ".rest", ".fit"}

MULTI_PART_TLDS = {"co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "co.uk", "com.au"}


def _extract_domain_parts_offline(url: str):
    """Extract (subdomain, domain, suffix) 100% offline with or without tldextract."""
    if _OFFLINE_EXTRACTOR is not None:
        ext = _OFFLINE_EXTRACTOR(url)
        return ext.subdomain.lower(), ext.domain.lower(), ext.suffix.lower()

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return "", "", ""
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
        return "", host, ""

    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        suffix = ".".join(parts[-2:])
        domain = parts[-3]
        subdomain = ".".join(parts[:-3])
    elif len(parts) >= 2:
        suffix = parts[-1]
        domain = parts[-2]
        subdomain = ".".join(parts[:-2])
    else:
        subdomain, domain, suffix = "", host, ""
    return subdomain, domain, suffix


def normalize_homoglyphs(text: str) -> str:
    """Normalize common visual trick replacements (homoglyphs)."""
    text = text.lower()
    text = text.replace("rn", "m")
    text = text.replace("0", "o")
    text = text.replace("1", "l")
    text = text.replace("3", "e")
    text = text.replace("vv", "w")
    return text


def analyze_url(url: str) -> dict:
    """Analyze a URL 100% locally for structural risks and brand typosquatting."""
    reasons = []
    risk_score = 0

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    subdomain, domain, suffix = _extract_domain_parts_offline(url)
    full_domain = f"{domain}.{suffix}" if suffix else domain
    normalized_domain = normalize_homoglyphs(domain)

    # 1. Check for HTTPS
    if parsed.scheme != "https":
        risk_score += 15
        reasons.append({"rule": "no_https", "score": 15, "reason": "URL does not use secure HTTPS"})

    # 2. Check for Risky TLDs
    if f".{suffix}" in RISKY_TLDS:
        risk_score += 30
        reasons.append({"rule": "risky_tld", "score": 30, "reason": f"Risky top-level domain (.{suffix}) detected"})

    # 3. IP Address Host Check
    ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if ip_pattern.match(domain) or ip_pattern.match(parsed.hostname or ""):
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
    if subdomain.count(".") > 1 or full_domain.count("-") > 2:
        risk_score += 20
        reasons.append({"rule": "excessive_subdomains_hyphens", "score": 20, "reason": "Unusually high number of subdomains or hyphens"})

    # 7. Brand Typosquatting Check against Indian Brands
    for brand in INDIAN_BRANDS:
        in_sub_or_path = brand in subdomain or brand in parsed.path.lower() or (brand in domain and domain != brand)
        if in_sub_or_path and domain != brand:
            risk_score += 40
            reasons.append({"rule": "brand_in_subdomain", "score": 40, "reason": f"Brand name '{brand}' used deceptively in domain/subdomain/path ('{full_domain}')"})
            break

        similarity = max(_similarity_ratio(brand, domain), _similarity_ratio(brand, normalized_domain))
        if 75 <= similarity < 100 and domain != brand:
            risk_score += 35
            reasons.append({"rule": "typosquatting", "score": 35, "reason": f"Domain looks suspiciously similar to trusted brand '{brand}' (typosquatting)"})
            break

    return {
        "url": url,
        "domain": full_domain,
        "risk_score": min(risk_score, 100),
        "reasons": reasons
    }
