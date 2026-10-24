import cv2
import numpy as np
import re
from urllib.parse import urlparse, parse_qs, unquote
from backend.urls import analyze_url, INDIAN_BRANDS
from backend.text_rules import analyze_message_text
from backend.db import check_blocklist
from backend.ml import predict_text_spam_ml

# Try importing pyzbar as a fallback QR/barcode decoder
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

# Offline list of common URL shorteners frequently abused in Quishing (QR Phishing)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd",
    "tiny.cc", "ow.ly", "rebrand.ly", "shorturl.at", "bl.ink", "v.gd",
    "qr.ae", "qrco.de", "qrfy.com", "lnkd.in"
}

# Offline list of high-risk file extensions dropped via QR codes
DANGEROUS_EXTENSIONS = (".apk", ".exe", ".bat", ".scr", ".msi", ".vbs", ".jar", ".zip", ".rar")

# Known Indian PSP / bank VPA handles for offline validation
KNOWN_UPI_HANDLES = {
    "ybl", "ibl", "axl", "okaxis", "okhdfcbank", "okicici", "oksbi",
    "paytm", "ptyes", "ptaxis", "pthdfc", "ptsbi", "apl", "rapl",
    "upi", "sbi", "hdfcbank", "icici", "axisbank", "kotak", "barodampay",
    "fbl", "indus", "pnb", "cnrb", "uboi", "mahb", "waicici", "wahdfcbank",
    "wasbi", "waaxis", "naviaxis", "jio", "freecharge", "airtel", "slice"
}


def decode_qr_image(image_bytes: bytes) -> str:
    """
    Multi-pass offline QR code decoder using OpenCV preprocessing
    (raw, grayscale, adaptive threshold, Otsu threshold, inverted dark-mode,
    and upscaled) with pyzbar fallback. Works 100% offline on screenshots
    and live webcam/phone camera frames.
    """
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

    if img is None:
        return ""

    detector = cv2.QRCodeDetector()
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Build candidate image variations for robust offline decoding
    candidates = [
        img,
        gray,
        cv2.bitwise_not(gray),  # Dark-mode QR codes (white modules on dark background)
        cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1],
        cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 10
        ),
    ]

    # If the image is very small or very large, add a resized pass
    h, w = gray.shape[:2]
    if max(h, w) < 400:
        candidates.append(cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC))
    elif max(h, w) > 1600:
        scale = 1000.0 / max(h, w)
        candidates.append(cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA))

    # 1. Try OpenCV QRCodeDetector across preprocessing passes
    for candidate in candidates:
        try:
            data, _, _ = detector.detectAndDecode(candidate)
            if data and data.strip():
                return data.strip()
            # Also try multi-QR detection if available
            retval, decoded_info, _, _ = detector.detectAndDecodeMulti(candidate)
            if retval and decoded_info:
                for item in decoded_info:
                    if item and item.strip():
                        return item.strip()
        except Exception:
            continue

    # 2. Fallback to pyzbar across candidate passes if installed
    if HAS_PYZBAR:
        for candidate in candidates[:4]:
            try:
                decoded_objects = pyzbar_decode(candidate)
                for obj in decoded_objects:
                    text = obj.data.decode("utf-8", errors="ignore").strip()
                    if text:
                        return text
            except Exception:
                continue

    return ""


def parse_upi_payload(upi_url: str) -> dict:
    """Parse a upi://pay or upi://mandate URI and extract all security-relevant parameters."""
    parsed = urlparse(upi_url)
    query_params = parse_qs(parsed.query)

    def get_param(key: str) -> str:
        return unquote(query_params.get(key, [""])[0]).strip()

    pa = get_param("pa")       # Payee VPA (e.g., merchant@ybl)
    pn = get_param("pn")       # Payee Name
    am = get_param("am")       # Pre-filled Amount
    mam = get_param("mam")     # Minimum Amount
    tn = get_param("tn")       # Transaction Note / Remarks
    mc = get_param("mc")       # Merchant Category Code (0000 or empty = unverified personal account)
    mode = get_param("mode")   # UPI mode (e.g., 04 = Mandate/Intent)
    sign = get_param("sign")   # Cryptographic signature (present on verified merchant QRs)
    orgid = get_param("orgid") # Organization ID
    url_param = get_param("url")

    is_mandate = (
        parsed.netloc.lower() == "mandate"
        or "mandate" in parsed.path.lower()
        or "recur" in query_params
        or "validitystart" in query_params
        or "validityend" in query_params
    )

    return {
        "payee_vpa": pa,
        "payee_name": pn,
        "amount": am,
        "min_amount": mam,
        "note": tn,
        "merchant_code": mc,
        "mode": mode,
        "is_signed": bool(sign),
        "org_id": orgid,
        "ref_url": url_param,
        "is_mandate": is_mandate,
    }


def analyze_upi_offline(payload: str, message_context: str = "") -> dict:
    """
    Deep offline heuristic analysis of UPI QR codes (upi://pay and upi://mandate).
    Detects 'Scan to Receive Money' traps, AutoPay mandate traps, hardcoded high amounts,
    brand/government impersonation via personal VPAs, and suspicious transaction notes.
    """
    upi = parse_upi_payload(payload)
    reasons = []
    risk_score = 0

    pa = upi["payee_vpa"].lower()
    pn = upi["payee_name"]
    am_str = upi["amount"]
    tn = upi["note"]
    mc = upi["merchant_code"]

    # Always inform user that UPI QR codes are for SENDING money, never receiving
    reasons.append({
        "rule": "upi_payment_outflow_notice",
        "score": 10,
        "reason": (
            f"UPI Payment QR to '{pn or 'Unknown'}' ({pa or 'No VPA'}). "
            "Remember: You NEVER need to scan a QR or enter a UPI PIN to receive money."
        )
    })
    risk_score += 10

    # 1. Check for UPI AutoPay / Recurring Mandate Trap
    if upi["is_mandate"]:
        risk_score += 55
        reasons.append({
            "rule": "upi_autopay_mandate",
            "score": 55,
            "reason": "UPI AutoPay / Recurring Mandate QR detected! Scanning this can authorize recurring automatic deductions from your bank account."
        })

    # 2. Check Pre-filled / Hardcoded Amount (am=)
    amount_val = 0.0
    if am_str:
        try:
            amount_val = float(am_str)
        except ValueError:
            amount_val = -1.0

        if amount_val < 0:
            risk_score += 25
            reasons.append({
                "rule": "upi_malformed_amount",
                "score": 25,
                "reason": f"Malformed pre-filled amount ('{am_str}') in UPI QR."
            })
        elif amount_val >= 2000:
            risk_score += 35
            reasons.append({
                "rule": "upi_high_prefilled_amount",
                "score": 35,
                "reason": f"QR code locks in a high pre-filled deduction of ₹{amount_val:,.2f}. Standard shop QRs let you type the amount yourself."
            })
        elif amount_val > 0:
            risk_score += 20
            reasons.append({
                "rule": "upi_prefilled_amount",
                "score": 20,
                "reason": f"QR code has a pre-filled payment amount of ₹{amount_val:,.2f} that will be deducted from your account."
            })

    # 3. Validate VPA structure & PSP handle offline
    if not pa or "@" not in pa:
        risk_score += 40
        reasons.append({
            "rule": "upi_invalid_vpa",
            "score": 40,
            "reason": "Missing or invalid UPI ID (VPA) structure inside QR payload."
        })
    else:
        vpa_user, vpa_handle = pa.split("@", 1)
        if vpa_handle not in KNOWN_UPI_HANDLES:
            risk_score += 20
            reasons.append({
                "rule": "upi_uncommon_handle",
                "score": 20,
                "reason": f"Uncommon or non-standard UPI handle '@{vpa_handle}'."
            })

        # Check if Payee Name claims to be an official brand/government/bank while using a personal phone-number VPA
        is_phone_vpa = bool(re.match(r"^(?:91)?[6-9]\d{9}$", vpa_user))
        is_unverified_merchant = (not mc or mc == "0000") and not upi["is_signed"]

        authority_terms = INDIAN_BRANDS + [
            "refund", "cashback", "official", "govt", "pm kisan", "rbi", "cyber",
            "police", "customs", "care", "helpline", "support", "kyc", "reward",
            "army", "canteen", "olx", "lottery", "prize", "bses", "tata power"
        ]
        pn_lower = pn.lower()
        matched_auth = [term for term in authority_terms if term in pn_lower or term in vpa_user]

        if matched_auth and (is_phone_vpa or is_unverified_merchant):
            risk_score += 45
            reasons.append({
                "rule": "upi_brand_impersonation",
                "score": 45,
                "reason": (
                    f"Payee name/VPA claims affiliation with '{matched_auth[0].upper()}', "
                    f"but uses an unverified personal UPI account ({pa})."
                )
            })
        elif is_unverified_merchant and amount_val > 0:
            risk_score += 15
            reasons.append({
                "rule": "upi_unverified_personal_qr",
                "score": 15,
                "reason": "QR belongs to an unverified personal UPI account (mc=0000 / unsigned) rather than a verified merchant."
            })

    # 4. Inspect Transaction Note (tn), Payee Name (pn), and Message Context for Scam Lures (English + Hindi/Hinglish)
    combined_text = f"{pn} {tn} {message_context}".strip()
    combined_lower = combined_text.lower()

    receive_lures = [
        "refund", "prize", "won", "cashback", "lottery", "reward", "claim",
        "receive", "credit", "bonus", "kyc", "electricity", "bill", "olx",
        "paisa paane", "refund milega", "inaam", "jeeta"
    ]
    if any(kw in combined_lower for kw in receive_lures):
        risk_score += 55
        reasons.append({
            "rule": "qr_refund_prize_trap",
            "score": 55,
            "reason": (
                "SCAM TRAP: 'Receive/Refund/Reward' lure paired with a UPI Payment QR! "
                "Scanning this will DEDUCT money from your account, not credit it."
            )
        })

    # Run TRU-LENS offline text rules & local ML model on combined note + context
    if combined_text:
        text_res = analyze_message_text(combined_text)
        for r in text_res["reasons"]:
            # Avoid duplicating the generic score if already caught, but add specific rule reasons
            risk_score += min(r["score"], 30)
            reasons.append(r)

        ml_proba = predict_text_spam_ml(combined_text)
        if ml_proba > 0.65:
            ml_pts = int(ml_proba * 30)
            risk_score += ml_pts
            reasons.append({
                "rule": "qr_ml_context_flag",
                "score": ml_pts,
                "reason": f"Offline ML model flagged the QR note/context as scam-like ({int(ml_proba * 100)}% confidence)."
            })

    return {
        "type": "upi",
        "risk_score": min(risk_score, 100),
        "in_blocklist": False,
        "reasons": reasons,
        "details": upi
    }


def analyze_qr_or_upi(payload: str, message_context: str = "") -> dict:
    """
    Comprehensive 100% offline analyzer for decoded QR payloads:
    - Case 1: UPI Payment & Mandate QRs (upi://pay, upi://mandate)
    - Case 2: Web URLs (Quishing, shorteners, APK drops, local SQLite blocklist, typosquatting)
    - Case 3: Device Action Traps (Call-forwarding USSD tel:, SIM-swap smsto:, Rogue WIFI:, inline data:/javascript:)
    - Case 4: Plain-text QR payloads (analyzed via offline text rules + local TF-IDF ML model)
    """
    if not payload or not payload.strip():
        return {"risk_score": 0, "in_blocklist": False, "reasons": [], "type": "empty", "details": {}}

    raw = payload.strip()
    raw_lower = raw.lower()

    # -------------------------------------------------------------------------
    # CASE 1: UPI Payment / Mandate QR (upi:// or BharatQR with pa=...@...)
    # -------------------------------------------------------------------------
    if raw_lower.startswith("upi://") or ("pa=" in raw_lower and "@" in raw_lower):
        if not raw_lower.startswith("upi://"):
            # Normalize raw query string if missing scheme
            raw = "upi://pay?" + raw.lstrip("?")
        return analyze_upi_offline(raw, message_context)

    # -------------------------------------------------------------------------
    # CASE 2: Dangerous Inline URI Schemes (javascript:, data:text/html)
    # -------------------------------------------------------------------------
    if raw_lower.startswith(("javascript:", "data:text/html", "vbscript:")):
        return {
            "type": "exploit_uri",
            "risk_score": 95,
            "in_blocklist": False,
            "reasons": [{
                "rule": "inline_code_uri",
                "score": 95,
                "reason": "QR encodes an executable script or embedded HTML phishing page (data:/javascript: URI) designed to steal credentials offline!"
            }],
            "details": {"payload": raw[:200]}
        }

    # -------------------------------------------------------------------------
    # CASE 3: Call Forwarding / USSD SIM-Hijack QR (tel:*21*, tel:*401*, etc.)
    # -------------------------------------------------------------------------
    if raw_lower.startswith("tel:"):
        dial_str = unquote(raw[4:]).strip()
        reasons = []
        score = 15
        # Check for USSD call/SMS forwarding codes (*21*, *401*, *61*, *62*, *67*, **21*, ##002#)
        if any(code in dial_str for code in ["*21*", "*401*", "*61*", "*62*", "*67*", "**", "#"]):
            score = 90
            reasons.append({
                "rule": "ussd_call_forwarding_scam",
                "score": 90,
                "reason": (
                    f"CRITICAL: QR triggers a USSD / Call-Forwarding code ({dial_str})! "
                    "Scammers use this to forward your calls and bank OTPs to their own phone."
                )
            })
        else:
            reasons.append({
                "rule": "tel_auto_dial",
                "score": 15,
                "reason": f"QR code initiates a phone call to {dial_str}. Verify this number independently before calling."
            })
        return {
            "type": "phone_ussd",
            "risk_score": score,
            "in_blocklist": False,
            "reasons": reasons,
            "details": {"dial_number": dial_str}
        }

    # -------------------------------------------------------------------------
    # CASE 4: Pre-filled SMS / SIM-Swap / UPI Binding Trap (smsto:, sms:, MATMSG:)
    # -------------------------------------------------------------------------
    if raw_lower.startswith(("smsto:", "sms:")):
        parts = raw.split(":", 2)
        recipient = parts[1] if len(parts) > 1 else "Unknown"
        sms_body = parts[2] if len(parts) > 2 else ""
        score = 45
        reasons = [{
            "rule": "qr_sms_trigger",
            "score": 45,
            "reason": f"QR pre-fills an outgoing SMS to '{recipient}'. Scammers use SMS QRs to trigger unauthorized UPI device binding or SIM swaps."
        }]
        if any(w in sms_body.lower() for w in ["port", "sim", "upi", "block", "kyc", "verify", "token"]):
            score = 85
            reasons.append({
                "rule": "sim_swap_or_binding_sms",
                "score": 40,
                "reason": f"SMS body contains SIM-porting or account-binding keywords ('{sms_body[:80]}'). Do NOT send this SMS!"
            })
        return {
            "type": "sms_trap",
            "risk_score": score,
            "in_blocklist": False,
            "reasons": reasons,
            "details": {"recipient": recipient, "sms_body": sms_body}
        }

    # -------------------------------------------------------------------------
    # CASE 5: Wi-Fi Configuration QR (WIFI:S:<SSID>;T:<WEP|WPA|nopass>;P:<pass>;;)
    # -------------------------------------------------------------------------
    if raw_lower.startswith("wifi:"):
        ssid_match = re.search(r"S:([^;]+);", raw, re.IGNORECASE)
        auth_match = re.search(r"T:([^;]+);", raw, re.IGNORECASE)
        ssid = ssid_match.group(1) if ssid_match else "Unknown Network"
        auth = (auth_match.group(1) if auth_match else "nopass").upper()
        score = 10
        reasons = []
        if auth in ("NOPASS", "NONE", "") or "WEP" in auth:
            score += 45
            reasons.append({
                "rule": "wifi_unencrypted_evil_twin",
                "score": 45,
                "reason": f"QR connects to an unencrypted/weak Wi-Fi network ('{ssid}', security: {auth}), which can intercept traffic via a local Evil-Twin attack."
            })
        else:
            reasons.append({
                "rule": "wifi_auto_connect",
                "score": 10,
                "reason": f"Wi-Fi auto-connect QR for SSID '{ssid}' ({auth}). Only join networks you trust."
            })
        return {
            "type": "wifi",
            "risk_score": score,
            "in_blocklist": False,
            "reasons": reasons,
            "details": {"ssid": ssid, "encryption": auth}
        }

    # -------------------------------------------------------------------------
    # CASE 6: URL Payload inside QR (Quishing)
    # -------------------------------------------------------------------------
    url_candidate = raw
    is_url = raw_lower.startswith(("http://", "https://", "www.")) or bool(
        re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.[a-zA-Z]{2,}(?:/.*)?$", raw)
    )
    if is_url:
        url_analysis = analyze_url(url_candidate)
        risk_score = url_analysis["risk_score"]
        reasons = list(url_analysis["reasons"])
        domain = url_analysis["domain"].lower()
        in_blocklist = False

        # 6a. Offline SQLite Blocklist Check
        if check_blocklist(domain) or check_blocklist(url_candidate):
            in_blocklist = True
            risk_score = 100
            reasons.append({
                "rule": "local_blocklist_match",
                "score": 100,
                "reason": f"Domain '{domain}' is listed in TRU-LENS offline scam blocklist!"
            })

        # 6b. URL Shortener Cloaking Check (high risk in QR codes)
        if domain in SHORTENER_DOMAINS:
            risk_score += 35
            reasons.append({
                "rule": "qr_url_shortener",
                "score": 35,
                "reason": f"QR code hides its true destination behind a URL shortener ({domain}). Legitimate organizations rarely double-mask links inside QR codes."
            })

        # 6c. Malicious APK / Executable File Drop Check
        parsed_url = urlparse(url_analysis["url"])
        path_lower = parsed_url.path.lower()
        query_lower = parsed_url.query.lower()
        if path_lower.endswith(DANGEROUS_EXTENSIONS) or ".apk" in path_lower or ".apk" in query_lower:
            risk_score += 65
            reasons.append({
                "rule": "qr_malicious_apk_drop",
                "score": 65,
                "reason": "DANGER: QR link points directly to a downloadable APK / executable file! Scammers use APK QRs to install banking spyware."
            })

        # 6d. Open Redirect / Phishing Path Keywords in URL
        phish_url_keywords = ["login", "verify", "kyc", "update", "secure", "account", "refund", "claim", "reward", "redirect="]
        matched_kw = [k for k in phish_url_keywords if k in path_lower or k in query_lower]
        if matched_kw:
            risk_score += 20
            reasons.append({
                "rule": "qr_phishing_path_keywords",
                "score": 20,
                "reason": f"URL path/query contains high-risk credential harvesting keywords: {', '.join(matched_kw[:3])}"
            })

        # 6e. Combine with optional message context if provided
        if message_context.strip():
            ctx_res = analyze_message_text(message_context)
            risk_score += ctx_res["rule_score"]
            reasons.extend(ctx_res["reasons"])

        return {
            "type": "url",
            "risk_score": min(risk_score, 100),
            "in_blocklist": in_blocklist,
            "reasons": reasons,
            "details": {"url": url_analysis["url"], "domain": domain}
        }

    # -------------------------------------------------------------------------
    # CASE 7: Plain-Text / Generic Payload (Run Offline Text Rules + Local ML)
    # -------------------------------------------------------------------------
    combined = f"{raw} {message_context}".strip()
    text_res = analyze_message_text(combined)
    risk_score = text_res["rule_score"]
    reasons = list(text_res["reasons"])

    ml_proba = predict_text_spam_ml(combined)
    if ml_proba > 0.6:
        ml_score = int(ml_proba * 40)
        risk_score += ml_score
        reasons.append({
            "rule": "ml_spam_detection",
            "score": ml_score,
            "reason": f"Offline ML model flagged text inside QR code (Confidence: {int(ml_proba * 100)}%)"
        })

    if not reasons:
        reasons.append({
            "rule": "generic_qr",
            "score": 0,
            "reason": "QR contains plain text with no known scam triggers."
        })

    return {
        "type": "text",
        "risk_score": min(risk_score, 100),
        "in_blocklist": False,
        "reasons": reasons,
        "details": {"payload": raw}
    }
