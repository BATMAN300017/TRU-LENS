import cv2
import numpy as np
from urllib.parse import urlparse, parse_qs
from backend.urls import analyze_url

# Try importing pyzbar as a fallback QR/barcode decoder
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except ImportError:
    HAS_PYZBAR = False

def decode_qr_image(image_bytes: bytes) -> str:
    """Decode a QR code from image bytes using OpenCV, with pyzbar fallback."""
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    if img is None:
        return ""

    # 1. Try OpenCV QRCodeDetector
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    if data:
        return data

    # 2. Fallback to pyzbar if available
    if HAS_PYZBAR:
        decoded_objects = pyzbar_decode(img)
        for obj in decoded_objects:
            return obj.data.decode('utf-8', errors='ignore')

    return ""

def parse_upi_payload(upi_url: str) -> dict:
    """Parse a upi://pay URI and extract payment parameters."""
    parsed = urlparse(upi_url)
    query_params = parse_qs(parsed.query)
    
    pa = query_params.get("pa", [""])[0]  # Payee address (VPA)
    pn = query_params.get("pn", [""])[0]  # Payee name
    am = query_params.get("am", [""])[0]  # Amount
    tn = query_params.get("tn", [""])[0]  # Transaction note / description
    
    return {
        "payee_vpa": pa,
        "payee_name": pn,
        "amount": am,
        "note": tn
    }

def analyze_qr_or_upi(payload: str, message_context: str = "") -> dict:
    """
    Analyze a decoded QR payload or direct UPI link.
    Flags scams where a refund/prize/collect message is paired with a payment QR.
    """
    reasons = []
    risk_score = 0
    extra_data = {}

    if not payload:
        return {"risk_score": 0, "reasons": [], "type": "empty"}

    # Case 1: UPI Payment Link
    if payload.startswith("upi://") or "pa=" in payload:
        upi_details = parse_upi_payload(payload)
        extra_data = upi_details
        
        reasons.append({
            "rule": "upi_intent_detected",
            "score": 10,
            "reason": f"UPI Payment link detected for VPA: {upi_details['payee_vpa'] or 'Unknown'}"
        })

        # Check if paired with suspicious message context (refund, lottery, prize, KYC)
        ctx_lower = message_context.lower()
        trap_keywords = ["refund", "prize", "won", "cashback", "lottery", "electricity", "kyc", "reward"]
        
        if any(kw in ctx_lower for kw in trap_keywords):
            risk_score += 50
            reasons.append({
                "rule": "qr_refund_prize_trap",
                "score": 50,
                "reason": "Suspicious message context (refund/prize/reward) paired with a payment QR code!"
            })
        else:
            risk_score += 15

        return {
            "type": "upi",
            "risk_score": risk_score,
            "reasons": reasons,
            "details": extra_data
        }

    # Case 2: URL payload inside QR
    elif payload.startswith(("http://", "https://", "www.")):
        url_analysis = analyze_url(payload)
        return {
            "type": "url",
            "risk_score": url_analysis["risk_score"],
            "reasons": url_analysis["reasons"],
            "details": {"url": payload, "domain": url_analysis["domain"]}
        }

    # Case 3: Generic text/unknown QR payload
    else:
        return {
            "type": "text",
            "risk_score": 0,
            "reasons": [{"rule": "generic_qr", "score": 0, "reason": "QR contains non-URL, non-UPI text payload"}],
            "details": {"payload": payload}
        }
