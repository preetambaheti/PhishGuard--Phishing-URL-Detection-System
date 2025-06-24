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


## 📊 Scoring Weights

| **Component**        | **Weight** |
|----------------------|------------|
| 🧠 Machine Learning   | 50%        |
| 🔒 SSL & WHOIS        | 20%        |
| 🌐 VirusTotal         | 15%        |
| 📝 Content Analysis   | 15%        |

---

## 📚 Credits & Tools

- 🧠 **Scikit-learn** – ML model training  
- 🔒 **ssl, whois, dns.resolver** – Domain & SSL inspection  
- 🌐 **VirusTotal Public API** – URL reputation scoring  
- 📄 **BeautifulSoup** – Page content parsing  
- ⚙️ **Flask** – Lightweight backend framework  
- 🎨 **HTML/CSS/JavaScript** – Frontend design

---

## 📜 License

This project is intended for **educational and academic use** only.  
For commercial deployment or production usage, please ensure proper **security audits and penetration testing**.
