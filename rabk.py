# Re-execute due to code execution state reset
# Re-save the combined phishing detection script as a file

combined_script = ""
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import networkx as nx
import ssl
import socket
from datetime import datetime
import whois
from dateutil.parser import parse

# ---------- SSL Checking Functions ----------

def get_ssl_certificate_info(hostname):
    context = ssl.create_default_context()
    try:
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        conn.settimeout(3)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        return cert
    except Exception:
        return None

def is_certificate_expired(cert):
    if not cert:
        return None
    expiry_str = cert.get('notAfter')
    if not expiry_str:
        return None
    try:
        expiry_date = parse(expiry_str)
        return expiry_date < datetime.utcnow()
    except:
        return None

# ---------- WHOIS Info Function ----------

def get_domain_info(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        expiration_date = info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return {
            "domain_name": info.domain_name,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "registrar": info.registrar
        }
    except:
        return None

# ---------- Rabin-Karp Analysis ----------

suspicious_keywords = [
    'login', 'verify', 'update', 'password', 'bank', 'credit card', 'payment',
    'secure', 'account', 'click here', 'urgent', 'alert', "enter.*password",
    "update.*account", "login.*securely", "click.*verify", "bank.*account",
    "unauthorized.*access", "your.*OTP", "confirm.*identity"
]

def rabin_karp_search(text, keyword, prime=101):
    m, n = len(keyword), len(text)
    d = 256
    h = pow(d, m-1) % prime
    p = t = 0
    result = []

    if m > n:
        return result

    for i in range(m):
        p = (d * p + ord(keyword[i])) % prime
        t = (d * t + ord(text[i])) % prime

    for s in range(n - m + 1):
        if p == t:
            if text[s:s + m] == keyword:
                result.append(keyword)
        if s < n - m:
            t = (d * (t - ord(text[s]) * h) + ord(text[s + m])) % prime
            if t < 0:
                t = t + prime
    return result

# ---------- Main Analyzer Class ----------

class RedirectGraphAnalyzer:
    def __init__(self, base_url, max_depth=2):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited = set()
        self.graph = nx.DiGraph()
        self.metadata = {}
        self.rk_keywords = set()
        self.redirects = {}

    def get_links(self, url):
        try:
            resp = requests.get(url, timeout=5)
            final_url = resp.url
            self.redirects[url] = final_url
            if 'text/html' not in resp.headers.get('Content-Type', ''):
                return []
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                if href.startswith('#') or href.lower().startswith('javascript:'):
                    continue
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                if parsed.scheme not in ['http', 'https']:
                    continue
                links.add(full_url)
            return list(links)
        except Exception as e:
            print(f"Error fetching links from {url}: {e}")
            return []

    def fetch_metadata(self, url):
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None

        ssl_cert = get_ssl_certificate_info(hostname)
        ssl_expired = is_certificate_expired(ssl_cert)
        whois_info = get_domain_info(hostname)

        return {
            "ssl_expired": ssl_expired,
            "whois": whois_info
        }

    def detect_keywords_rk(self, text):
        found = set()
        for keyword in suspicious_keywords:
            if rabin_karp_search(text.lower(), keyword.lower()):
                found.add(keyword)
        return found

    def analyze_page(self, url):
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            visible_text = soup.get_text(separator=' ', strip=True)
            found_keywords = self.detect_keywords_rk(visible_text)
            self.rk_keywords.update(found_keywords)
        except:
            pass

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.base_url
        if depth > self.max_depth or url in self.visited:
            return

        print(f"Crawling [{depth}]: {url}")
        self.visited.add(url)

        self.metadata[url] = self.fetch_metadata(url)
        self.analyze_page(url)

        links = self.get_links(url)
        for link in links:
            self.graph.add_edge(url, link)
            self.crawl(link, depth + 1)

    def print_report(self):
        print("\\n=== Crawl Summary ===")
        print(f"Total URLs visited: {len(self.visited)}")
        print(f"Total edges in graph: {self.graph.number_of_edges()}")

        cycles = list(nx.simple_cycles(self.graph))
        if cycles:
            print(f"\\nDetected Cycles ({len(cycles)}):")
            for i, cycle in enumerate(cycles, 1):
                print(f"Cycle {i}:")
                for url in cycle:
                    print(f"  - {url}")
        else:
            print("\\nNo cycles detected.")

        print("\\n=== Redirects Detected ===")
        for k, v in self.redirects.items():
            if k != v:
                print(f"  {k} -> {v}")

        print("\\n=== Suspicious Keywords Detected ===")
        print(self.rk_keywords if self.rk_keywords else "None")

        print("\\n=== Metadata Summary ===")
        for url, meta in self.metadata.items():
            print(f"\\nURL: {url}")
            if meta is None:
                print("  Metadata fetch failed.")
                continue
            ssl_exp = meta.get("ssl_expired")
            whois = meta.get("whois")
            print(f"  SSL Certificate expired? {ssl_exp}")
            if whois:
                print(f"  WHOIS domain: {whois.get('domain_name')}")
                print(f"  Registrar: {whois.get('registrar')}")
                print(f"  Created on: {whois.get('creation_date')}")
                print(f"  Expires on: {whois.get('expiration_date')}")
            else:
                print("  WHOIS info not available.")

if __name__ == "__main__":
    start_url = input("Enter starting URL (with http/https): ").strip()
    analyzer = RedirectGraphAnalyzer(start_url, max_depth=2)
    analyzer.crawl()
    analyzer.print_report()


file_path = "/mnt/data/phishing_redirect_analyzer.py"
with open(file_path, "w") as f:
    f.write(combined_script)

file_path
