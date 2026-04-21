import pandas as pd
import requests
from bs4 import BeautifulSoup
import json
import concurrent.futures 

class TechScanner:
    def __init__(self):
        self.signatures = {
            "Shopify": {
                "scripts": ["cdn.shopify.com", "shopify-payment-button"],
                "meta": ["shopify"]
            },
            "WordPress": {
                "scripts": ["wp-content", "wp-includes"],
                "meta": ["wordpress", "generator"]
            },
            "Google Analytics": {
                "scripts": ["google-analytics.com", "gtag.js", "analytics.js"]
            },
            "Cloudflare": {
                "headers": ["cf-ray", "server: cloudflare"],
                "scripts": ["/cdn-cgi/"]
            },
            "React": {
                "scripts": ["react.production", "_reactroot"]
            }
        }

    def scan_site(self, domain):
        report = {"domain": domain, "found": [], "proofs": []}
        url = f"http://{domain}"
        
        try:
            session = requests.Session()
            response = session.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            html_raw = response.text.lower()
            headers_raw = str(response.headers).lower()

            for tech, rules in self.signatures.items():
                is_detected = False
                
                for script in soup.find_all('script', src=True):
                    for sign in rules.get("scripts", []):
                        if sign in script['src'].lower():
                            report["found"].append(tech)
                            report["proofs"].append(f"[{tech}] Found script source: {sign}")
                            is_detected = True
                            break
                    if is_detected: break
                
                if not is_detected and "headers" in rules:
                    for sign in rules["headers"]:
                        if sign in headers_raw:
                            report["found"].append(tech)
                            report["proofs"].append(f"[{tech}] Found in HTTP Headers: {sign}")
                            is_detected = True
                            break

                if not is_detected and "meta" in rules:
                    for meta in soup.find_all('meta'):
                        content = str(meta.get('content', '')).lower()
                        for sign in rules["meta"]:
                            if sign in content:
                                report["found"].append(tech)
                                report["proofs"].append(f"[{tech}] Found in Meta Tag: {sign}")
                                is_detected = True
                                break
                        if is_detected: break
            
            report["found"] = list(set(report["found"]))
            return report

        except Exception as e:
            return {"domain": domain, "error": str(e)}

def run_pro_scanner():
    df = pd.read_parquet('part-00000-66e0628d-2c7f-425a-8f5b-738bcd6bf198-c000.snappy.parquet')
    domains = df['root_domain'].unique().tolist()
    
    scanner = TechScanner()
    final_results = []

    print(f"Scanning {len(domains)} domains in parallel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(scanner.scan_site, domains))
    
    with open('detected_technologies_final.json', 'w') as f:
        json.dump(results, f, indent=4)
    print("Done! Check detected_technologies_final.json")

if __name__ == "__main__":
    run_pro_scanner()