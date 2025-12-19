from header_parser import parse_eml
from spf_dkim_checker import (
    check_spf,
    check_dkim,
    check_dmarc,
    authentication_summary
)
from phishing_checks import (
    detect_spoofing,
    detect_display_name_impersonation,
    detect_suspicious_domain,
    detect_received_chain_anomalies,
    phishing_score
)
from vt_checker import check_urls
from pdf_report import generate_pdf


def analyze_email(file_path):
    headers, body = parse_eml(file_path)

    spf = check_spf(headers)
    dkim = check_dkim(headers)
    dmarc = check_dmarc(headers)
    auth_status = authentication_summary(spf, dkim, dmarc)

    spoofing = detect_spoofing(headers)
    impersonation = detect_display_name_impersonation(headers)
    suspicious_domain = detect_suspicious_domain(headers)
    received_anomaly = detect_received_chain_anomalies(headers)

    score = phishing_score(
        spf,
        dkim,
        dmarc,
        spoofing,
        impersonation,
        suspicious_domain
    )

    vt_results = check_urls(body)

    report_path = generate_pdf(
        headers=headers,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        spoofing=spoofing,
        score=score,
        vt=vt_results
    )

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "authentication": auth_status,
        "spoofing": spoofing,
        "impersonation": impersonation,
        "suspicious_domain": suspicious_domain,
        "received_anomaly": received_anomaly,
        "score": score,
        "virustotal": vt_results,
        "report": report_path
    }

if __name__ == "__main__":
    result = analyze_email("samples/phishing.eml")
    print(result)
