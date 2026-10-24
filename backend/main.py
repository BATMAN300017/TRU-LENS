from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os
import re

from backend.redact import redact_text
from backend.urls import analyze_url
from backend.qr_upi import decode_qr_image, analyze_qr_or_upi
from backend.text_rules import analyze_message_text
from backend.ml import predict_text_spam_ml
from backend.scoring import calculate_verdict
from backend.db import check_blocklist, save_feedback

app = FastAPI(title="Tru-lens Local Engine", version="1.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    text: str


class AnalyzeQRPayloadRequest(BaseModel):
    payload: str
    message_context: str = ""


@app.post("/api/analyze")
def analyze_content(payload: AnalyzeRequest):
    raw_text = payload.text

    # 1. Redaction Layer (Runs FIRST)
    redaction_res = redact_text(raw_text)
    safe_text = redaction_res["masked_text"]

    total_score = 0
    all_reasons = []

    # Check if the user pasted a direct UPI URI into the text box
    if raw_text.strip().lower().startswith("upi://"):
        qr_res = analyze_qr_or_upi(raw_text.strip(), "")
        verdict_res = calculate_verdict(
            qr_res["risk_score"], in_blocklist=qr_res.get("in_blocklist", False)
        )
        return {
            "redacted_text": safe_text,
            "redactions_applied": redaction_res["redactions_applied"],
            "score": qr_res["risk_score"],
            "verdict": verdict_res["verdict"],
            "color": verdict_res["color"],
            "reasons": qr_res["reasons"],
            "online_check": "not used (offline mode)",
        }

    # 2. Text Analysis (Rules + ML)
    text_analysis = analyze_message_text(safe_text)
    total_score += text_analysis["rule_score"]
    all_reasons.extend(text_analysis["reasons"])

    ml_proba = predict_text_spam_ml(safe_text)
    if ml_proba > 0.6:
        ml_score = int(ml_proba * 40)
        total_score += ml_score
        all_reasons.append({
            "rule": "ml_spam_detection",
            "score": ml_score,
            "reason": f"Machine Learning model flagged text pattern (Confidence: {int(ml_proba * 100)}%)",
        })

    # 3. Extract and check URLs inside the text
    url_pattern = re.compile(
        r"https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
    )
    urls_found = url_pattern.findall(raw_text)

    in_blocklist = False
    for u in urls_found:
        url_res = analyze_url(u)
        total_score += url_res["risk_score"]
        all_reasons.extend(url_res["reasons"])
        if check_blocklist(url_res["domain"]):
            in_blocklist = True
            all_reasons.append({
                "rule": "local_blocklist_match",
                "score": 100,
                "reason": f"Domain {url_res['domain']} found in offline local blocklist!",
            })

    # 4. Final Verdict calculation
    total_score = min(total_score, 100)
    verdict_res = calculate_verdict(total_score, in_blocklist=in_blocklist)

    return {
        "redacted_text": safe_text,
        "redactions_applied": redaction_res["redactions_applied"],
        "score": total_score,
        "verdict": verdict_res["verdict"],
        "color": verdict_res["color"],
        "reasons": all_reasons,
        "online_check": "not used (offline mode)",
    }


@app.post("/api/analyze-qr")
async def analyze_qr(file: UploadFile = File(...), message_context: str = Form("")):
    """
    Offline QR Code image & camera frame analyzer.
    Accepts either an uploaded image file or a captured video frame blob from the live camera.
    """
    contents = await file.read()
    decoded_payload = decode_qr_image(contents)

    if not decoded_payload:
        raise HTTPException(
            status_code=400,
            detail="No QR code detected in the image. Try a clearer image or hold the QR steady in front of the camera.",
        )

    qr_result = analyze_qr_or_upi(decoded_payload, message_context)
    in_blocklist = qr_result.get("in_blocklist", False)
    verdict_res = calculate_verdict(qr_result["risk_score"], in_blocklist=in_blocklist)
    redacted_res = redact_text(
        f"{decoded_payload} | Context: {message_context}" if message_context else decoded_payload
    )

    return {
        "decoded_payload": decoded_payload,
        "redacted_text": redacted_res["masked_text"],
        "analysis_type": qr_result["type"],
        "score": verdict_res["score"],
        "verdict": verdict_res["verdict"],
        "color": verdict_res["color"],
        "default_advice": verdict_res["default_advice"],
        "reasons": qr_result["reasons"],
        "details": qr_result.get("details", {}),
        "online_check": "not used (100% offline engine)",
    }


@app.post("/api/analyze-qr-payload")
def analyze_qr_payload_endpoint(req: AnalyzeQRPayloadRequest):
    """
    Direct offline analyzer when a QR payload string is already decoded
    (e.g., via browser BarcodeDetector API or pasted UPI URI).
    """
    decoded_payload = req.payload.strip()
    if not decoded_payload:
        raise HTTPException(status_code=400, detail="Empty QR payload provided.")

    qr_result = analyze_qr_or_upi(decoded_payload, req.message_context)
    in_blocklist = qr_result.get("in_blocklist", False)
    verdict_res = calculate_verdict(qr_result["risk_score"], in_blocklist=in_blocklist)
    redacted_res = redact_text(
        f"{decoded_payload} | Context: {req.message_context}" if req.message_context else decoded_payload
    )

    return {
        "decoded_payload": decoded_payload,
        "redacted_text": redacted_res["masked_text"],
        "analysis_type": qr_result["type"],
        "score": verdict_res["score"],
        "verdict": verdict_res["verdict"],
        "color": verdict_res["color"],
        "default_advice": verdict_res["default_advice"],
        "reasons": qr_result["reasons"],
        "details": qr_result.get("details", {}),
        "online_check": "not used (100% offline engine)",
    }


class FeedbackRequest(BaseModel):
    redacted_input: str
    predicted_verdict: str
    user_label: str


@app.post("/api/feedback")
def submit_feedback(payload: FeedbackRequest):
    save_feedback(payload.redacted_input, payload.predicted_verdict, payload.user_label)
    return {"status": "success", "message": "Feedback saved securely."}


FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))


@app.get("/")
def serve_home():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": f"index.html not found! Make sure it is saved at: {index_path}"}


if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
