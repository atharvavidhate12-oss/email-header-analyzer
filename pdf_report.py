from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
import os

def generate_pdf(headers, spf, dkim, dmarc, spoofing, score, vt):
    filename = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()

    content = []
    content.append(Paragraph("<b>Email Security Analysis Report</b>", styles["Title"]))

    content.append(Paragraph(f"SPF: {spf}", styles["Normal"]))
    content.append(Paragraph(f"DKIM: {dkim}", styles["Normal"]))
    content.append(Paragraph(f"DMARC: {dmarc}", styles["Normal"]))
    content.append(Paragraph(f"Spoofing Detected: {spoofing}", styles["Normal"]))
    content.append(Paragraph(f"Phishing Score: {score}", styles["Normal"]))

    content.append(Paragraph("<b>VirusTotal URL Scan</b>", styles["Heading2"]))
    for v in vt:
        content.append(Paragraph(f"{v['url']} → {v['status']}", styles["Normal"]))

    doc.build(content)
    return filename
