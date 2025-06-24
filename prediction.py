# prediction.py (Threshold-adjusted, 28 features, using best model)
import re
import socket
import requests
import datetime
from urllib.parse import urlparse
import pandas as pd
import joblib
import ssl

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    print("Warning: dnspython not installed (pip install dnspython). MX record check will be skipped.")
    DNS_AVAILABLE = False

PHISHING_BLACKLIST = {
    "evil-login.com",
    "secure-payment-update.net",
    "verify-account-details.xyz",
    "giftcard-claim-now.info",
    "mysafebankhttps.com"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "account", "update", "verify",
    "password", "banking", "confirm", "authentication", "recovery"
]

def get_domain_from_url(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        if '@' in domain:
            domain = domain.split('@')[-1]
        if domain.lower().startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return None

def having_ip_address(url):
    try:
        domain = urlparse(url).netloc.split(':')[0]
        socket.inet_aton(domain)
        return -1
    except:
        return -1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 1

def url_length(url):
    length = len(url)
    return 1 if length < 54 else (0 if length <= 75 else -1)

def shortening_service(url):
    return -1 if re.search(r"bit\.ly|goo\.gl|tinyurl", url) else 1

def having_at_symbol(url):
    return -1 if "@" in url else 1

def double_slash_redirecting(url):
    last_double_slash = url.rfind('//')
    path_start = url.find('/', url.find('://') + 3)
    return -1 if path_start != -1 and last_double_slash > path_start else 1

def prefix_suffix(url):
    domain = get_domain_from_url(url)
    return -1 if domain and '-' in domain else 1

def having_sub_domain(url):
    domain = get_domain_from_url(url)
    if not domain: return -1
    count = domain.count('.')
    return 1 if count == 1 else (0 if count == 2 else -1)

def ssl_final_state(url):
    try:
        if urlparse(url).scheme != 'https': return -1
        requests.get(url, verify=True, timeout=5)
        return 1
    except requests.exceptions.SSLError:
        return -1
    except:
        return 0

def favicon(response): return 1

def port(url):
    port = urlparse(url).port
    return 1 if port in [None, 80, 443] else -1

def https_token(url):
    domain = get_domain_from_url(url)
    path = urlparse(url).path
    return -1 if 'https' in domain.lower() or path.lower().startswith('/https') else 1

def request_url(response): return 1

def url_of_anchor(response): return 1

def links_in_tags(response): return 1

def sfh(response): return 1

def submitting_to_email(response): return 1

def abnormal_url(url, domain):
    if domain in PHISHING_BLACKLIST: return -1
    path_query = urlparse(url).path + '?' + urlparse(url).query
    if any(k in path_query.lower() for k in SUSPICIOUS_KEYWORDS): return -1
    return 1

def redirect(response): return 0 if not response else (1 if len(response.history) <= 1 else (0 if len(response.history) < 4 else -1))

def on_mouseover(response): return 1

def right_click(response): return 1

def popup_window(response): return 1

def iframe(response): return 1

def dns_record(domain):
    try:
        socket.gethostbyname(domain)
        if DNS_AVAILABLE:
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                if not answers: return 0
            except:
                return 0
        return 1
    except:
        return -1

def web_traffic(url): return 0

def page_rank(url): return -1

def google_index(url): return 1

def links_pointing_to_page(response): return 0

def statistical_report(url, domain):
    return -1 if domain in PHISHING_BLACKLIST else 1

def extract_features(url):
    features = [1] * 28
    try:
        domain = get_domain_from_url(url)
        response = None
        try:
            response = requests.get(url, timeout=10, verify=True, allow_redirects=True)
        except:
            response = None

        dns_exists = dns_record(domain)
        net_fail = (dns_exists == -1 or response is None)

        features[0] = having_ip_address(url)
        features[1] = url_length(url)
        features[2] = shortening_service(url)
        features[3] = having_at_symbol(url)
        features[4] = double_slash_redirecting(url)
        features[5] = prefix_suffix(url)
        features[6] = having_sub_domain(url)
        features[7] = ssl_final_state(url)
        features[8] = -1 if net_fail else favicon(response)
        features[9] = port(url)
        features[10] = https_token(url)
        features[11] = -1 if net_fail else request_url(response)
        features[12] = -1 if net_fail else url_of_anchor(response)
        features[13] = -1 if net_fail else links_in_tags(response)
        features[14] = -1 if net_fail else sfh(response)
        features[15] = -1 if net_fail else submitting_to_email(response)
        features[16] = abnormal_url(url, domain)
        features[17] = 0 if net_fail else redirect(response)
        features[18] = -1 if net_fail else on_mouseover(response)
        features[19] = -1 if net_fail else right_click(response)
        features[20] = -1 if net_fail else popup_window(response)
        features[21] = -1 if net_fail else iframe(response)
        features[22] = dns_exists
        features[23] = -1 if net_fail else web_traffic(url)
        features[24] = page_rank(url)
        features[25] = -1 if net_fail else google_index(url)
        features[26] = -1 if net_fail else links_pointing_to_page(response)
        features[27] = statistical_report(url, domain)
    except Exception as e:
        print(f"Major error during feature extraction for {url}: {e}")
        return [-1] * 28
    return features

try:
    model = joblib.load("phishing_model_best.pkl")
    scaler = joblib.load("scaler.pkl")
except:
    print("Error loading model or scaler. Make sure model.py was run after CSV cleanup.")
    exit()

if __name__ == "__main__":
    while True:
        url = input("Enter URL to check (or type 'quit' to exit): ")
        if url.lower() == 'quit': break
        if not url.startswith('http://') and not url.startswith('https://'):
            print("Assuming https:// for the URL.")
            url = 'https://' + url

        print(f"\nExtracting features for: {url}")
        features = extract_features(url)

        if len(features) != 28:
            print(f"Error: Feature extraction returned {len(features)} features, expected 28.")
            continue

        print(f"Raw features: {features}")

        try:
            input_df = pd.DataFrame([features], columns=[
                'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
                'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
                'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
                'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect',
                'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'DNSRecord',
                'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
                'Statistical_report'
            ])
            features_scaled = scaler.transform(input_df)
        except Exception as e:
            print(f"Error scaling features: {e}")
            continue

        try:
            probability = model.predict_proba(features_scaled)[0][1]  # Probability of phishing
        except Exception as e:
            print(f"Error during prediction: {e}")
            continue

        print("-" * 30)
        if probability >= 0.7:
            print(f"\U0001F6A8 High Risk: Phishing Website (Confidence: {probability*100:.2f}%)")
        elif 0.4 <= probability < 0.7:
            print(f"⚠️ Suspicious Website (Confidence: {probability*100:.2f}%)")
        else:
            print(f"✅ Legitimate Website (Confidence: {(1 - probability)*100:.2f}%)")
        print("-" * 30 + "\n")
