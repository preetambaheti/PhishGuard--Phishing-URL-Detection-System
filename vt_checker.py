import requests
import os
import sys
import time
import argparse
import hashlib
import base64
from dotenv import load_dotenv

def get_vt_report_smart(url_to_check: str, api_key: str):
    """
    Retrieves a VirusTotal report for a URL using an optimized method.
    1. Checks for an existing report (fast).
    2. Submits for a new scan if no report exists (slower).

    Returns:
        The JSON report dictionary from VirusTotal, or None if an error occurs.
    """
    if not api_key:
        print("ERROR: VIRUSTOTAL_API_KEY not found.", file=sys.stderr)
        return None

    headers = {"x-apikey": api_key}
    
    # The VirusTotal API uses a specific ID for URLs. It's the SHA-256 hash of the URL.
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

    # === STEP 1: Check for an EXISTING report (the fast path) ===
    print(f"Checking for existing report for: {url_to_check}", file=sys.stderr)
    existing_report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(existing_report_endpoint, headers=headers, timeout=15)
        if response.status_code == 200:
            print("Found existing report. No wait needed.", file=sys.stderr)
            return response.json()
        elif response.status_code != 404:
            # Handle other errors besides "Not Found"
            print(f"Error checking existing report: {response.status_code} {response.text}", file=sys.stderr)
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to VirusTotal: {e}", file=sys.stderr)
        return None
    
    # === STEP 2: If no report exists, submit for a NEW scan (the slow path) ===
    print("No existing report found. Submitting for a new analysis.", file=sys.stderr)
    try:
        scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url_to_check}, timeout=15)
        scan_response.raise_for_status()
        analysis_id = scan_response.json()["data"]["id"]
    except requests.exceptions.RequestException as e:
        print(f"Error submitting new URL: {e}", file=sys.stderr)
        return None

    # Wait for the new analysis to complete
    print("Waiting for new analysis to complete (approx. 15 seconds)...", file=sys.stderr)
    time.sleep(15)
    
    analysis_report_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    try:
        report_response = requests.get(analysis_report_endpoint, headers=headers, timeout=15)
        report_response.raise_for_status()
        return report_response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving new report: {e}", file=sys.stderr)
        return None

def classify_from_report(report: dict) -> str:
    """Parses a report to produce a 'phishing' or 'legitimate' classification."""
    if not report or "data" not in report:
        return "phishing"  # Fail-safe

    # The report structure is slightly different for existing vs. new reports.
    # We check both possible locations for the stats.
    attributes = report["data"].get("attributes", {})
    stats = attributes.get("last_analysis_stats") or attributes.get("stats")

    if not stats:
        return "phishing" # Could not find stats block

    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)

    if malicious_count > 0 or suspicious_count > 0:
        return "phishing"
    
    return "legitimate"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Efficiently classify a URL using the VirusTotal API.")
    parser.add_argument("url", help="The full URL to classify.")
    args = parser.parse_args()
    
    load_dotenv()
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not vt_api_key:
        print("phishing")
        sys.exit(1)

    analysis_report = get_vt_report_smart(args.url, vt_api_key)
    classification = classify_from_report(analysis_report)
    
    print(classification)