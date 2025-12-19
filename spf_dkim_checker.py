import re

def check_spf(headers):
    """
    Checks SPF result from email headers
    """
    spf_header = headers.get("Received-SPF", "")
    if "pass" in spf_header.lower():
        return "PASS"
    elif "fail" in spf_header.lower():
        return "FAIL"
    elif "softfail" in spf_header.lower():
        return "SOFTFAIL"
    return "UNKNOWN"


def check_dkim(headers):
    """
    Checks DKIM authentication status
    """
    auth_results = headers.get("Authentication-Results", "")
    if "dkim=pass" in auth_results.lower():
        return "PASS"
    elif "dkim=fail" in auth_results.lower():
        return "FAIL"
    return "UNKNOWN"


def check_dmarc(headers):
    """
    Checks DMARC alignment
    """
    auth_results = headers.get("Authentication-Results", "")
    if "dmarc=pass" in auth_results.lower():
        return "PASS"
    elif "dmarc=fail" in auth_results.lower():
        return "FAIL"
    return "UNKNOWN"


def authentication_summary(spf, dkim, dmarc):
    """
    Overall authentication verdict
    """
    if spf == "PASS" and dkim == "PASS" and dmarc == "PASS":
        return "AUTHENTICATED"
    if spf == "FAIL" and dkim == "FAIL":
        return "HIGH RISK"
    return "SUSPICIOUS"
