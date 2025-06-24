from flask import Flask, request, jsonify, send_from_directory
from prediction import extract_features, model, scaler
from ssl_utils import get_ssl_certificate_info, analyze_ssl, is_certificate_expired, get_domain_info, get_dns_ttl, get_mx_records, score_phishing_risk
from urllib.parse import urlparse
import pandas as pd
import os
import traceback
import requests
import time
import base64  # <-- ADDED for VirusTotal URL ID generation
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, static_url_path='', static_folder='.')

# ML Model Column Names
COLUMNS = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
    'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect',
    'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'DNSRecord',
    'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

# Scoring weights
WEIGHTS = {
    'ml_weight': 0.50,
    'ssl_weight': 0.20,
    'vt_weight': 0.15,
    'content_weight': 0.15
}

# Risk thresholds
RISK_THRESHOLDS = {
    'legitimate': 0.4,
    'suspicious': 0.7
}

# --- Normalization and Analysis Functions ---

def normalize_ml_score(ml_probability):
    return ml_probability

def normalize_ssl_score(cert, whois_info, ttl, mx_records):
    try:
        score, reasons, _ = score_phishing_risk(cert, whois_info, ttl, mx_records, [], False)
        return min(score / 10.0, 1.0), reasons
    except Exception as e:
        return 0.5, [f"SSL analysis failed: {e}"]

def analyze_page_content(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        has_password_field = bool(soup.find('input', {'type': 'password'}))
        has_form = bool(soup.find('form'))
        return {"has_password_field": has_password_field, "has_form": has_form}
    except Exception as e:
        raise Exception(f"Could not fetch or parse content: {e}")

def normalize_content_score(analysis_data):
    score, reasons = 0.0, []
    if analysis_data.get("has_password_field"):
        score += 0.5
        reasons.append("Contains a password input field")
    if analysis_data.get("has_form"):
        score += 0.1
        reasons.append("Contains a data submission form")
    return min(score, 1.0), reasons

# VirusTotal function
def analyze_virustotal_smart(url):
    """
    Retrieves a VirusTotal report for a URL using an optimized method.
    1. Checks for an existing report (fast).
    2. Submits for a new scan if no report exists (slower).
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise Exception("VirusTotal API Key not configured.")
    
    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Step 1: Check for an existing report
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if response.status_code == 200:
            print(f"VT: Found existing report for {url}")
            return response.json()
    except requests.exceptions.RequestException as e:
        print(f"VT Error (checking existing): {e}")

    # Step 2: If no existing report, submit for a new scan
    print(f"VT: No existing report. Submitting for new scan: {url}")
    try:
        scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=10)
        scan_response.raise_for_status()
        analysis_id = scan_response.json()["data"]["id"]
        
        # Wait for analysis to complete
        print("VT: Waiting for new analysis to complete...")
        time.sleep(15) 
        
        report_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10)
        report_response.raise_for_status()
        return report_response.json()
    except requests.exceptions.RequestException as e:
         raise Exception(f"VirusTotal submission/retrieval failed: {e}")

def normalize_vt_score(vt_data):
    """Convert VirusTotal stats to a risk score. Handles both old and new reports."""
    if not vt_data or "data" not in vt_data:
        return 0.0, ["Invalid VT report"]

    attributes = vt_data["data"].get("attributes", {})
    # Handle both direct analysis reports and existing URL reports
    stats = attributes.get("last_analysis_stats") or attributes.get("stats")
    
    if not stats:
        return 0.0, ["No analysis stats found"]

    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)
    
    reasons, score = [], 0.0
    if malicious_count > 1: score = 1.0; reasons.append(f"{malicious_count} engines flagged as malicious")
    elif malicious_count == 1: score = 0.8; reasons.append("1 engine flagged as malicious")
    if suspicious_count > 0: score = min(score + 0.2, 1.0); reasons.append(f"{suspicious_count} engines flagged as suspicious")
    if not reasons: reasons.append("No threats detected by VirusTotal")
        
    return score, reasons

# --- Final Score Calculation ---
def calculate_final_risk_score(ml_score, ssl_score, vt_score, content_score):
    final_score = (
        ml_score * WEIGHTS['ml_weight'] + ssl_score * WEIGHTS['ssl_weight'] + 
        vt_score * WEIGHTS['vt_weight'] + content_score * WEIGHTS['content_weight']
    )
    return min(final_score, 1.0)

def get_risk_verdict(final_score):
    if final_score <= RISK_THRESHOLDS['legitimate']: return "Legitimate ✅", "low"
    if final_score <= RISK_THRESHOLDS['suspicious']: return "Suspicious ⚠️", "medium"
    return "Phishing 🚨", "high"

# --- Flask Routes ---
@app.route("/")
def serve_index(): return send_from_directory('.', 'index.html')

@app.route("/main.html")
def serve_main(): return send_from_directory('.', 'main.html')

@app.route("/scan", methods=["POST"])
def scan_url():
    data = request.get_json()
    url = data.get("url")
    if not url: return jsonify({"error": "No URL provided"}), 400
    if not url.startswith("http"): url = "https://" + url

    try:
        domain = urlparse(url).netloc
        response_data = {"url": url, "domain": domain, "components": {}, "final_assessment": {}}

        # Component 1: ML Model
        try:
            features = extract_features(url)
            ml_prob = model.predict_proba(scaler.transform(pd.DataFrame([features], columns=COLUMNS)))[0][1]
            ml_risk_score = normalize_ml_score(ml_prob)
            response_data["components"]["ml_analysis"] = {"risk_score": round(ml_risk_score, 3), "confidence": f"{ml_prob*100:.1f}%"}
        except Exception as e: ml_risk_score = 0.5; response_data["components"]["ml_analysis"] = {"risk_score": 0.5, "error": str(e)}

        # Component 2: SSL & Infrastructure
        try:
            cert, whois = get_ssl_certificate_info(url), get_domain_info(domain)
            ssl_risk_score, ssl_reasons = normalize_ssl_score(cert, whois, get_dns_ttl(domain), get_mx_records(domain))
            response_data["components"]["ssl_analysis"] = {"risk_score": round(ssl_risk_score, 3), "ssl_status": analyze_ssl(cert), "ssl_expired": is_certificate_expired(cert), "whois_registrar": whois.get("registrar") if whois else "N/A", "risk_factors": ssl_reasons}
        except Exception as e: ssl_risk_score = 0.5; response_data["components"]["ssl_analysis"] = {"risk_score": 0.5, "error": str(e)}

        # Component 3: VirusTotal Reputation (Smart)
        try:
            vt_data = analyze_virustotal_smart(url)
            vt_risk_score, vt_reasons = normalize_vt_score(vt_data)
            # We only need to send the stats to the frontend, not the whole report
            stats = (vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats") or 
                     vt_data.get("data", {}).get("attributes", {}).get("stats"))
            response_data["components"]["vt_analysis"] = {"risk_score": round(vt_risk_score, 3), "details": {"stats": stats}, "risk_factors": vt_reasons}
        except Exception as e: vt_risk_score = 0.0; response_data["components"]["vt_analysis"] = {"risk_score": 0.0, "error": str(e)}

        # Component 4: Content Analysis
        try:
            content_data = analyze_page_content(url)
            content_risk_score, content_reasons = normalize_content_score(content_data)
            response_data["components"]["content_analysis"] = {
                "risk_score": round(content_risk_score, 3),
                "details": content_data,
                "risk_factors": content_reasons
            }
        # --- THIS IS THE CORRECTED LOGIC ---
        # Catch the specific network/connection error first
        except requests.exceptions.RequestException as network_error:
            user_friendly_error = "Could not connect to the website. It may be offline or the domain does not exist."
            # A non-existent site is suspicious, so assign a moderate risk score.
            content_risk_score = 0.6 
            print(f"Content Analysis Network Error: {network_error}") # Keep detailed log for yourself
            
            # Send the user-friendly error to the UI
            response_data["components"]["content_analysis"] = {
                "risk_score": content_risk_score, 
                "error": user_friendly_error
            }
        # Catch any other general exceptions that might occur (e.g., parsing)
        except Exception as e:
            user_friendly_error = "Failed to analyze the page's content due to an unexpected issue."
            content_risk_score = 0.2
            print(f"Content Analysis General Error: {e}") # Keep detailed log for yourself
            
            # Send the user-friendly error to the UI
            response_data["components"]["content_analysis"] = {
                "risk_score": content_risk_score, 
                "error": user_friendly_error
            }
        # --- END OF CORRECTED LOGIC ---
        # Final Calculation
        final_risk_score = calculate_final_risk_score(ml_risk_score, ssl_risk_score, vt_risk_score, content_risk_score)
        verdict, level = get_risk_verdict(final_risk_score)
        
        response_data["final_assessment"] = {
            "final_risk_score": round(final_risk_score, 3), "risk_percentage": round(final_risk_score * 100, 1),
            "verdict": verdict, "risk_level": level, "scoring_weights": WEIGHTS,
            "component_scores": {"ml_score": round(ml_risk_score, 3), "ssl_score": round(ssl_risk_score, 3), "vt_score": round(vt_risk_score, 3), "content_score": round(content_risk_score, 3)},
            "recommendation": "⚠️ DO NOT VISIT" if level == "high" else "⚠️ Exercise caution" if level == "medium" else "✅ Appears safe"
        }
        return jsonify(response_data)
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"error": f"General analysis failed: {e}", "url": url}), 500

if __name__ == "__main__":
    print("🚀 Starting Enhanced PhishGuard Server...")
    print(f"📊 Scoring Weights: ML={WEIGHTS['ml_weight']}, SSL={WEIGHTS['ssl_weight']}, VT={WEIGHTS['vt_weight']}, Content={WEIGHTS['content_weight']}")
    app.run(debug=True, host='0.0.0.0', port=5000)