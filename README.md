# 📧 Email Header Analyzer

A cybersecurity-focused web application that analyzes email headers to detect **spoofing attempts**, **SPF/DKIM authentication issues**, and **phishing indicators**.  
This tool is designed for **learning, awareness, and defensive security analysis**.

---

## 🚀 Features

### 🔍 Header Parsing
- Extracts key email header fields:
  - From
  - To
  - Return-Path
  - Received
  - Message-ID
- Identifies sender and mail transfer path

### 🛡️ SPF & DKIM Analysis
- Detects presence of SPF and DKIM records
- Flags missing or failed authentication
- Helps identify **email spoofing risks**

### 🎣 Phishing Detection
- Checks for common phishing indicators:
  - Mismatch between `From` and `Return-Path`
  - Suspicious domains
  - Multiple relay hops
- Assigns a **phishing risk level**

### 🌐 Web-Based UI
- Clean and user-friendly interface
- Paste raw email headers and analyze instantly
- Color-coded results for better visibility

---

## 🧠 Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS (Jinja2 templates)
- **Security Logic:** Custom Python modules
- **Environment:** Virtualenv

⚠️ Disclaimer

This tool is intended for educational and defensive security purposes only.
Do NOT use this tool for unauthorized or malicious activities.

## ⚙️ Installation & Setup

### 1️⃣ Clone the Repository
#bash
git clone https://github.com/<your-username>/email-header-analyzer.git
cd email-header-analyzer

2️⃣ Create Virtual Environment
bash
Copy code
python -m venv venv
Activate it:

Windows

bash
Copy code
venv\Scripts\activate
Linux / macOS

bash
Copy code
source venv/bin/activate
3️⃣ Install Dependencies
bash
Copy code
pip install -r requirements.txt
▶️ Running the Application
bash
Copy code
python app.py
Open your browser and go to:

cpp
Copy code
http://127.0.0.1:5000

🧪 How to Use

Open the web app
Paste the full email header
Click Analyze
View:
SPF / DKIM status
Phishing indicators
Risk assessment
