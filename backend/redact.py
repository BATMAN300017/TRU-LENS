import re

def redact_text(text: str) -> dict:
    """
    Masks sensitive PII (Aadhaar, PAN, phone numbers, bank account numbers, 
    OTPs/PINs, and emails) before any processing, logging, or storage.
    Returns the masked text and a summary of redactions applied.
    """
    if not text:
        return {"masked_text": "", "redactions_applied": []}

    redacted_text = text
    redactions_made = set()

    # 1. Aadhaar Number (12 digits, optional spaces or hyphens)
    aadhaar_pattern = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')
    if aadhaar_pattern.search(redacted_text):
        redacted_text = aadhaar_pattern.sub('[Aadhaar Redacted]', redacted_text)
        redactions_made.add('Aadhaar')

    # 2. PAN Card Number (Format: 5 uppercase letters, 4 digits, 1 uppercase letter)
    pan_pattern = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', re.IGNORECASE)
    if pan_pattern.search(redacted_text):
        redacted_text = pan_pattern.sub('[PAN Redacted]', redacted_text)
        redactions_made.add('PAN')

    # 3. Phone Numbers (Indian formats: +91 or 10 digits starting with 6-9)
    phone_pattern = re.compile(r'(?:\+91[\-\s]?)?[6-9]\d{9}\b|\b\d{5}[\-\s]?\d{5}\b')
    if phone_pattern.search(redacted_text):
        redacted_text = phone_pattern.sub('[Phone Redacted]', redacted_text)
        redactions_made.add('Phone Number')

    # 4. Bank Account Numbers (9 to 18 digits standalone)
    for match in re.finditer(r'\b\d{9,18}\b', redacted_text):
        num_str = match.group(0)
        # Avoid double-replacing already masked patterns or years
        if len(num_str) >= 9 and not num_str.startswith("20"):
            redacted_text = redacted_text.replace(num_str, '[Account Redacted]')
            redactions_made.add('Bank Account')

    # 5. OTPs / PINs (4 to 8 digits near keywords like otp, code, pin, verification)
    for match in re.finditer(r'\b(\d{4,8})\b', redacted_text):
        num_str = match.group(1)
        start_pos = max(0, match.start() - 25)
        end_pos = min(len(redacted_text), match.end() + 25)
        context = redacted_text[start_pos:end_pos].lower()
        if any(kw in context for kw in ['otp', 'code', 'pin', 'verification', 'password', 'pwd']):
            redacted_text = redacted_text.replace(num_str, '[OTP/PIN Redacted]')
            redactions_made.add('OTP/PIN')

    # 6. Email Addresses
    email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    if email_pattern.search(redacted_text):
        redacted_text = email_pattern.sub('[Email Redacted]', redacted_text)
        redactions_made.add('Email')

    return {
        "masked_text": redacted_text,
        "redactions_applied": list(redactions_made)
    }
