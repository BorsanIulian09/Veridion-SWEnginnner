import pandas as pd
import requests
from bs4 import BeautifulSoup
import json
import concurrent.futures

class TechScanner:
    def __init__(self):
        self.signatures = {
            # e-commerce
            "Shopify": {"scripts": ["cdn.shopify.com", "shopify-payment-button"], "meta": ["shopify"]},
            "WordPress": {"scripts": ["wp-content", "wp-includes"], "meta": ["wordpress", "generator"]},
            "WooCommerce": {"scripts": ["woocommerce"], "meta": ["woocommerce"]},
            "Magento": {"scripts": ["mage/cookies", "magento_"], "headers": ["x-magento-init"]},
            "Wix": {"scripts": ["wix.com", "wix-static"], "headers": ["x-wix-request-id"]},
            "Squarespace": {"scripts": ["squarespace.com", "static.squarespace"], "headers": ["server: squarespace"]},
            "Webflow": {"meta": ["webflow"]},
            "Joomla": {"scripts": ["/media/system/js/core.js", "/media/jui/js/"], "meta": ["joomla"]},
            
            # analitics 
            "Google Analytics": {"scripts": ["google-analytics.com", "gtag.js", "analytics.js", "googletagmanager"]},
            "Facebook Pixel": {"scripts": ["connect.facebook.net/en_us/fbevents.js", "fbq("]},
            "Hotjar": {"scripts": ["static.hotjar.com", "hjSettings"]},
            "TikTok Pixel": {"scripts": ["analytics.tiktok.com"]},
            "LinkedIn Insights": {"scripts": ["snap.licdn.com"]},
            "Yandex Metrika": {"scripts": ["mc.yandex.ru/metrika"]},
            
            # js frameworks
            "React": {"scripts": ["react.production", "_reactroot", "react-dom.production"]},
            "Vue.js": {"scripts": ["vue.min.js", "vue.js", "__vue__"]},
            "Angular": {"scripts": ["angular.min.js", "angular.js", "ng-version"]},
            "jQuery": {"scripts": ["jquery.min.js", "jquery.js", "jquery-core"]},
            "Bootstrap": {"scripts": ["bootstrap.min.js", "bootstrap.bundle.min.js", "bootstrap.css"]},
            "Tailwind CSS": {"scripts": ["tailwindcss.com", "tailwind.min.css"]},
            "Next.js": {"scripts": ["_next/static"], "meta": ["next-head"]},
            "Nuxt.js": {"scripts": ["_nuxt/"]},
            "Moment.js": {"scripts": ["moment.min.js"]},
            "Lodash": {"scripts": ["lodash.min.js"]},
            #security, CDN
            "Cloudflare": {"headers": ["cf-ray", "server: cloudflare"], "scripts": ["/cdn-cgi/"]},
            "Amazon CloudFront": {"headers": ["x-amz-cf-id", "server: cloudfront"]},
            "Akamai": {"headers": ["x-akamai-request-id"]},
            "Fastly": {"headers": ["x-fastly-request-id", "server: fastly"]},
            "Varnish": {"headers": ["x-varnish"]},
            "Nginx": {"headers": ["server: nginx"]},
            "Apache": {"headers": ["server: apache"]},
            #marketing 
            "Stripe": {"scripts": ["js.stripe.com", "m.stripe.network"]},
            "PayPal": {"scripts": ["paypal.com/sdk", "paypalobjects.com"]},
            "Klarna": {"scripts": ["klarna.com"]},
            "Google Pay": {"scripts": ["pay.google.com"]},
            "Apple Pay": {"scripts": ["applepay.js"]},
            #customer support
            "Mailchimp": {"scripts": ["chimpstatic.com", "mc.us"]},
            "Intercom": {"scripts": ["widget.intercom.io"]},
            "Zendesk": {"scripts": ["static.zdassets.com"]},
            "HubSpot": {"scripts": ["js.hs-scripts.com", "js.hs-analytics.net"]},
            "Tawk.to": {"scripts": ["embed.tawk.to"]}
        }

    def scan_site(self, domain):
        report = {"domain": domain, "found": [], "proofs": []}
        url = f"http://{domain}"
        
        try:
            session = requests.Session()
            response = session.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            soup = BeautifulSoup(response.text, 'html.parser')
            html_raw = response.text.lower()
            headers_raw = str(response.headers).lower()

            for tech, rules in self.signatures.items():
                is_detected = False
                
                for script in soup.find_all('script', src=True):
                    for sign in rules.get("scripts", []):
                        if sign.lower() in script['src'].lower():
                            report["found"].append(tech)
                            report["proofs"].append(f"[{tech}] Found script source: {sign}")
                            is_detected = True
                            break
                    if is_detected: break
                
                if not is_detected and "scripts" in rules:
                    for sign in rules["scripts"]:
                        if sign.lower() in html_raw:
                             report["found"].append(tech)
                             report["proofs"].append(f"[{tech}] Found keyword in HTML: {sign}")
                             is_detected = True
                             break

                if not is_detected and "headers" in rules:
                    for sign in rules["headers"]:
                        if sign.lower() in headers_raw:
                            report["found"].append(tech)
                            report["proofs"].append(f"[{tech}] Found in HTTP Headers: {sign}")
                            is_detected = True
                            break

                if not is_detected and "meta" in rules:
                    for meta in soup.find_all('meta'):
                        content = str(meta.get('content', '')).lower()
                        name = str(meta.get('name', '')).lower()
                        for sign in rules["meta"]:
                            if sign.lower() in content or sign.lower() in name:
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
    try:
        df = pd.read_parquet('part-00000-66e0628d-2c7f-425a-8f5b-738bcd6bf198-c000.snappy.parquet')
        domains = df['root_domain'].unique().tolist()
    except Exception as e:
        print(f"Eroare la citirea fisierului: {e}")
        return
    
    scanner = TechScanner()

    print(f"Scanning {len(domains)} domains in parallel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        results = list(executor.map(scanner.scan_site, domains))
    toate_tehnologiile_gasite = set()
    domenii_cu_erori = 0
    
    for rezultat in results:
        if "found" in rezultat:
            for tech in rezultat["found"]:
                toate_tehnologiile_gasite.add(tech)
        elif "error" in rezultat:
            domenii_cu_erori += 1
            
    total_unice = len(toate_tehnologiile_gasite)
    # ------------------------------------------------

    with open('detected_technologies_final.json', 'w') as f:
        json.dump(results, f, indent=4)
        
    
    print(" SCANARE FINALIZATĂ!")
    
    print(f"Domenii scanate: {len(domains)}")
    print(f"Domenii cu erori/timeout: {domenii_cu_erori}")
    print(f"TEHNOLOGII UNICE GĂSITE: {total_unice}")
    
    print("Rezultatele complete și dovezile au fost salvate în 'detected_technologies_final.json'.")

if __name__ == "__main__":
    run_pro_scanner()