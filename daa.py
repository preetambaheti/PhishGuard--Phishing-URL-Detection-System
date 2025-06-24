import pandas as pd
from urllib.parse import urlparse
from rapidfuzz import process, fuzz

# Extract domain from URL
def extract_domain(url):
    try:
        hostname = urlparse(url).netloc
        return hostname.replace('www.', '').lower()
    except:
        return ""

# Normalize visually misleading characters
def normalize_visually(domain):
    replacements = {
        '0': 'o',
        '1': 'i',
        '3': 'e',
        '5': 's',
        '@': 'a',
        '7': 't',
        '$': 's'
    }
    for fake_char, real_char in replacements.items():
        domain = domain.replace(fake_char, real_char)
    return domain

# Load and normalize trusted domains
def load_domains(filename):
    df = pd.read_csv(filename)
    raw_domains = df['Domain'].dropna().str.lower().str.strip().tolist()
    normalized_map = {
        domain: normalize_visually(domain)
        for domain in raw_domains
    }
    return normalized_map

# Compare with normalized trusted domains
def check_domain_similarity(input_domain, trusted_domain_map, threshold=88):
    norm_input = normalize_visually(input_domain)

    # Use list of normalized domains for matching
    normalized_trusted = list(trusted_domain_map.values())

    results = process.extract(
        norm_input,
        normalized_trusted,
        scorer=fuzz.WRatio,
        limit=3
    )

    for match_norm, score, idx in results:
        if score >= threshold:
            original_match = list(trusted_domain_map.keys())[idx]
            return {
                "input_domain": input_domain,
                "normalized": norm_input,
                "matched_domain": original_match,
                "similarity_score": score,
                "phishing_flag": 1
            }

    return {
        "input_domain": input_domain,
        "normalized": norm_input,
        "matched_domain": None,
        "similarity_score": 0,
        "phishing_flag": 0
    }

# Main loop
def main():
    trusted_map = load_domains('trimmed_domains.csv')
    print(f"🔐 Loaded {len(trusted_map)} trusted domains.")

    while True:
        url = input("\n🔎 Enter a URL to check (or type 'exit' to quit): ").strip()
        if url.lower() == 'exit':
            print("👋 Exiting.")
            break

        if not url.startswith("http"):
            url = "http://" + url

        domain = extract_domain(url)
        result = check_domain_similarity(domain, trusted_map)

        print(f"\n✅ Extracted domain: {result['input_domain']}")
        print(f"🔁 Normalized domain: {result['normalized']}")
        if result["phishing_flag"]:
            print(f"⚠️  Potential phishing detected!")
            print(f"   - Matched with: {result['matched_domain']}")
            print(f"   - Similarity Score: {result['similarity_score']}%")
        else:
            print("✅ No strong similarity with top domains.")

if __name__ == "__main__":
    main()
