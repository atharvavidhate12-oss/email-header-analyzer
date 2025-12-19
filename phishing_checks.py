import re

SUSPICIOUS_DOMAINS = [
    "paypa1", "goog1e", "micros0ft",
    "faceb00k", "secure-login", "verify"
]

def extract_domain(email):
    match = re.search(r'@([\w\.-]+)', email)
    return match.group(1).lower() if match else ""


def detect_spoofing(headers):
    """
    Detect From vs Return-Path mismatch
    """
    from_header = headers.get("From", "")
    return_path = headers.get("Return-Path", "")

    from_domain = extract_domain(from_header)
    return_domain = extract_domain(return_path)

    return from_domain and return_domain and from_domain != return_domain


def detect_display_name_impersonation(headers):
    """
    Detect fake brand display names
    """
    from_header = headers.get("From", "")
    return any(brand.lower() in from_header.lower()
               for brand in ["paypal", "google", "microsoft", "amazon"])


def detect_suspicious_domain(headers):
    """
    Detect look-alike domains
    """
    from_header = headers.get("From", "")
    domain = extract_domain(from_header)

    return any(s in domain for s in SUSPICIOUS_DOMAINS)


def detect_received_chain_anomalies(headers):
    """
    Detect unusual mail server hops
    """
    received = headers.get("Received", "")
    return "unknown" in received.lower() or "localhost" in received.lower()


def phishing_score(spf, dkim, dmarc, spoofing, impersonation, suspicious_domain):
    """
    Risk scoring model (SOC style)
    """
    score = 0

    if spf in ["FAIL", "SOFTFAIL"]:
        score += 25
    if dkim == "FAIL":
        score += 25
    if dmarc == "FAIL":
        score += 20
    if spoofing:
        score += 20
    if impersonation:
        score += 10
    if suspicious_domain:
        score += 15

    return min(score, 100)
