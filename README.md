# 🛡️ PhishGuard - Phishing URL Detection System

**PhishGuard** is an intelligent, multi-layered web application that detects phishing URLs using a combination of:
- 🔍 Machine Learning
- 🔒 SSL Certificate & WHOIS analysis
- 🌐 VirusTotal API scanning
- 📝 Page content & keyword inspection (via Rabin-Karp)

It provides real-time analysis, risk scoring, and a clear security verdict to help users avoid malicious websites.

---

## 🚀 Features

- ✅ **Machine Learning Prediction**
  - Trained on 28 handcrafted features
  - Random Forest classifier with hyperparameter tuning
- 🔐 **SSL and Domain Infrastructure Analysis**
  - Checks SSL issuer, certificate expiry, domain age, DNS TTL, MX records
- 🌍 **VirusTotal Reputation Check**
  - Queries 90+ antivirus engines via the VirusTotal API
- 📄 **Page Content Inspection**
  - Detects login forms and suspicious keywords using Rabin-Karp algorithm
- 🧠 **Overall Risk Scoring**
  - Weighted score calculation with clear verdict: Legitimate ✅ / Suspicious ⚠️ / Phishing 🚨
