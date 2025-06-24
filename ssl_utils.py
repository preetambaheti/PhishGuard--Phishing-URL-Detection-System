# Required Libraries
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from dateutil.parser import parse
import whois
import dns.resolver
import traceback

# List of Trusted SSL Certificate Issuers
TRUSTED_ISSUERS = ["Let's Encrypt", "DigiCert", "Sectigo", "GoDaddy", "GlobalSign", "Comodo"]

# Date Parsing Cache
_parse_cache = {}

# Function to check SSL certificate expiry
def is_certificate_expired(cert) -> str | bool:
    if not cert or isinstance(cert, str):
        return 'Unknown'
    
    expiry_str = cert.get('notAfter')
    if not expiry_str:
        return 'No Expiry Info'

    if expiry_str in _parse_cache:
        return _parse_cache[expiry_str]

    try:
        expiry_date = parse(expiry_str)
        expired = expiry_date < datetime.utcnow()
        _parse_cache[expiry_str] = expired
        return expired
    except Exception:
        print(f"⚠️ Date Parsing Error for expiry string: {expiry_str}")
        _parse_cache[expiry_str] = 'Date Parsing Error'
        return 'Date Parsing Error'

# Helper for safe date parsing
def safe_parse_date(date_value):
    if date_value is None:
        return None
    if isinstance(date_value, list):
        date_value = date_value[0]
    if isinstance(date_value, datetime):
        return date_value
    try:
        return parse(str(date_value))
    except Exception:
        return None

# SSL Certificate Fetching
def get_ssl_certificate_info(url: str):
    parsed_url = urlparse(url)
    hostnames = [parsed_url.netloc or parsed_url.path]
    if not hostnames[0].startswith('www.'):
        hostnames.append('www.' + hostnames[0])

    context = ssl.create_default_context()
    for hostname in hostnames:
        try:
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
            conn.settimeout(5)
            conn.connect((hostname, 443))
            return conn.getpeercert()
        except ssl.SSLError as e:
            print(f"⚠️ SSL Error for {hostname}: {e}")
        except socket.gaierror:
            print(f"❌ DNS Resolution Failed for {hostname}")
        except socket.timeout:
            print(f"❌ SSL Connection Timed Out for {hostname}")
        except Exception as e:
            print(f"❌ General SSL Error for {hostname}: {e}")
    return None

# Analyze SSL Issuer
def analyze_ssl(cert) -> str:
    if not cert or isinstance(cert, str):
        return 'Invalid or SSL Fetch Failed'

    issuer = cert.get('issuer')
    try:
        issuer_name = ' '.join(x[0][1] for x in issuer if isinstance(x[0], tuple)) if issuer else "Unknown"
    except Exception as e:
        issuer_name = f"Error extracting issuer name: {e}"

    for trusted in TRUSTED_ISSUERS:
        if trusted.lower() in issuer_name.lower():
            return f'Valid (Trusted Issuer: {issuer_name})'
    return f'Self-signed or Untrusted Issuer: {issuer_name}'

# WHOIS Domain Info
def get_domain_info(domain: str) -> dict | None:
    try:
        info = whois.whois(domain)
        return {
            "domain_name": info.domain_name,
            "creation_date": safe_parse_date(info.creation_date),
            "expiration_date": safe_parse_date(info.expiration_date),
            "registrar": info.registrar,
            "name_servers": info.name_servers,
            "status": info.status,
            "whois_name": info.name,
        }
    except Exception as e:
        print(f"❌ WHOIS lookup failed for {domain}: {e}")
        print("📍 Debug Info:")
        print(traceback.format_exc())
        return None

# Get DNS TTL
def get_dns_ttl(domain: str):
    try:
        answer = dns.resolver.resolve(domain, 'A')
        return answer.rrset.ttl
    except Exception as e:
        print(f"⚠️ DNS TTL check failed for {domain}: {e}")
        return None

# Get MX Records
def get_mx_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [r.exchange.to_text() for r in answers]
    except Exception as e:
        print(f"⚠️ DNS MX check failed for {domain}: {e}")
        return []

# Get TXT Records
def get_txt_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [r.to_text() for r in answers]
    except Exception as e:
        print(f"⚠️ DNS TXT check failed for {domain}: {e}")
        return []

# Scoring System
def score_phishing_risk(cert, whois_info, ttl, mx_records, txt_records, keywords_found=False):
    score = 0
    reasons = []

    # SSL Checks
    if not cert:
        score += 2
        reasons.append("Missing or Invalid SSL")
    else:
        issuer = cert.get('issuer')
        try:
            issuer_name = ' '.join(x[0][1] for x in issuer if isinstance(x[0], tuple)) if issuer else ""
        except:
            issuer_name = "Unknown"

        if not any(trusted.lower() in issuer_name.lower() for trusted in TRUSTED_ISSUERS):
            score += 2
            reasons.append("Self-signed or Untrusted SSL")

        if is_certificate_expired(cert) == True:
            score += 1
            reasons.append("Expired SSL Certificate")

    # WHOIS Checks
    if whois_info:
        creation = whois_info.get('creation_date')
        expiration = whois_info.get('expiration_date')
        whois_name = whois_info.get('whois_name')

        if creation and (datetime.utcnow() - creation).days < 180:
            score += 2
            reasons.append("Domain age < 6 months")
        if expiration and (expiration - datetime.utcnow()).days < 30:
            score += 1
            reasons.append("Domain expiring soon")
        if whois_name and any(word in str(whois_name).lower() for word in ['redacted', 'privacy', 'proxy', 'protected']):
            score += 1
            reasons.append("WHOIS Privacy Protection Enabled")
    else:
        score += 2
        reasons.append("Missing WHOIS Info")

    # DNS TTL
    if ttl is not None and ttl < 300:
        score += 1
        reasons.append("Low DNS TTL")

    # MX Check
    if not mx_records:
        score += 1
        reasons.append("No MX Records found")

    # Keywords
    if keywords_found:
        score += 2
        reasons.append("Suspicious Keywords Found in Page")

    verdict = "⚠️ Phishing Suspected" if score >= 5 else "✅ Likely Legitimate"
    return score, reasons, verdict

# Main Execution
if __name__ == "__main__":
    url = input("Enter a website URL: ").strip()
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc or parsed_url.path

    print(f"\n🔍 Checking SSL certificate for: {hostname}")
    cert = get_ssl_certificate_info(url)
    print("🔐 SSL Issuer Analysis:", analyze_ssl(cert))
    print("⏳ SSL Expired?:", is_certificate_expired(cert))

    print("\n📜 WHOIS Domain Info:")
    whois_data = get_domain_info(hostname)
    print(whois_data)

    print("\n🌐 DNS TTL Value:")
    ttl_value = get_dns_ttl(hostname)
    print(ttl_value)

    print("\n✉️ DNS MX Records:")
    mx_records = get_mx_records(hostname)
    print(mx_records)

    print("\n📝 DNS TXT Records:")
    txt_records = get_txt_records(hostname)
    print(txt_records)

    print("\n🧠 Scoring for Phishing Risk:")
    score, reasons, verdict = score_phishing_risk(cert, whois_data, ttl_value, mx_records, txt_records, keywords_found=False)
    print(f"🔢 Final Score: {score}")
    print("📌 Reasons:")
    for reason in reasons:
        print(f" - {reason}")
    print(f"🎯 Verdict: {verdict}")
