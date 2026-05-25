# 🛡️ PhishSentinel

> **Automated Phishing Email Triage Platform for SOC Analysts**

PhishSentinel is a production-grade phishing analysis tool that replicates the full manual SOC triage workflow — header inspection, URL reputation, and body language analysis — into a single automated pipeline. Upload a suspicious `.eml` file and get a structured, SOC-grade verdict in seconds.

---

## 🔍 What Problem Does It Solve?

Phishing is the #1 attack vector across organizations. SOC analysts waste hours manually investigating suspicious emails one by one — checking headers, hunting URLs, reading body text for red flags. PhishSentinel automates that entire process into one analyst-facing dashboard.

---

## ⚙️ Three-Layer Detection Engine

PhishSentinel runs three detection modules **simultaneously** on every email:

| Layer | Module | What It Checks |
|-------|--------|----------------|
| 1 | **Header Authentication** | SPF, DKIM, DMARC validation — detects spoofed sender domains |
| 2 | **URL Reputation** | Live VirusTotal API calls on every extracted URL — returns real-time malicious/suspicious engine counts |
| 3 | **NLP Body Analysis** | Detects urgency language, credential harvesting phrases, and brand impersonation patterns |

All three scores are combined into a **single weighted verdict engine**.

---

## 🚨 SOC-Grade Verdict Output

Output is not just "suspicious" or "safe." PhishSentinel produces:

- **Severity Level** → `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- **Confidence Score** → Percentage confidence in verdict
- **Score Breakdown** → Per-module contribution to final score
- **Flag Detail** → Every triggered flag with its point contribution
- **Analyst Recommendation** → Specific next-step action

Structured exactly like a real SOC incident report.

---

## 🖥️ Analyst Dashboard

PhishSentinel is not a terminal script. It ships with a **dark-themed web UI** where analysts can:

- Upload any `.eml` file via drag-and-drop
- Watch analysis execute in real time
- View full verdict with all flags, scores, and URL reputations rendered visually

Designed to look and feel like a deployable SOC product.

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, Flask |
| NLP Analysis | Python NLP (keyword + pattern matching) |
| Threat Intelligence | VirusTotal API (live calls) |
| Header Parsing | Python `email` library |
| Frontend | HTML/CSS, Jinja2 (dark-themed UI) |
| Email Format | `.eml` file support |
| ML Classification | TF-IDF Vectorizer + Logistic Regression (scikit-learn) |
---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- VirusTotal API key (free tier works) → [Get one here](https://www.virustotal.com/gui/join-us)

### Installation

```bash
# Clone the repo
git clone https://github.com/Sakshamm-Thakurr/PhishSentinel.git
cd PhishSentinel

# Create virtual environment
python -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Create a .env file in the root directory
touch .env
```

Add your API key to `.env`:
```
VIRUSTOTAL_API_KEY=your_api_key_here
```

### Run

```bash
python app.py
```

Open your browser at `http://localhost:5000`

---

## 📁 Project Structure

```
PhishSentinel/
├── app.py                  # Flask app entry point
├── requirements.txt        # Dependencies
├── .env                    # API keys (not committed)
├── .gitignore
├── modules/
│   ├── header_analyzer.py  # SPF/DKIM/DMARC parsing
│   ├── url_analyzer.py     # VirusTotal API integration
│   ├── body_analyzer.py    # NLP phishing detection
│   └── verdict_engine.py   # Weighted scoring + verdict
├── templates/
│   └── index.html          # Analyst dashboard UI
├── static/
│   └── style.css           # Dark theme styles
└── samples/
    └── sample.eml          # Test email for demo
```

---

## 🧪 Sample Output

```
===== PhishSentinel Verdict =====
Severity   : CRITICAL
Confidence : 94%

Module Scores:
  Header Auth    : 35/35  [FAIL — SPF & DKIM both failed]
  URL Reputation : 40/40  [3/72 VT engines flagged malicious]
  Body Analysis  : 19/25  [Urgency language + credential harvesting detected]

Flags Triggered:
  [+35] SPF check failed — sender domain mismatch
  [+40] URL flagged malicious by VirusTotal (3 engines)
  [+12] Urgency language detected: "immediate action required"
  [+7]  Credential harvesting phrase: "verify your account"

Recommendation: BLOCK sender domain. Escalate to Tier 2. Preserve email headers for forensics.
=================================
```

---

## 🎯 Use Cases

- SOC Tier 1 analyst phishing triage
- Security awareness training simulations
- Email security posture assessment
- CTF forensics challenges

---

## 📋 Roadmap

- [ ] Attachment analysis (macro detection, file hash lookup)
- [ ] MITRE ATT&CK technique tagging per verdict
- [ ] Splunk HEC integration for centralized logging
- [ ] Bulk `.eml` folder analysis mode
- [ ] REST API endpoint for SOAR integration

---

## 🔗 Connect

**Saksham Thakur**  
M.Tech Cybersecurity — Thapar University  
[LinkedIn](https://www.linkedin.com/in/saksham-thakur-244450268/) • [GitHub](https://github.com/Sakshamm-Thakurr) • [TryHackMe — Top 5%](https://tryhackme.com)

---

> *Built as part of an ongoing SOC-focused security portfolio. Feedback and contributions welcome.*
