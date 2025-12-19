import requests
import re

VT_API_KEY = ""

def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)

def check_urls(text):
    urls = extract_urls(text)
    results = []

    for url in urls:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )
        if response.status_code == 200:
            results.append({"url": url, "status": "Submitted"})
        else:
            results.append({"url": url, "status": "Error"})

    return results
