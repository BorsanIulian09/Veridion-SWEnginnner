import pandas as pd
import requests
import json

def scanner():
    
    df = pd.read_parquet('part-00000-66e0628d-2c7f-425a-8f5b-738bcd6bf198-c000.snappy.parquet')
    domains = df['root_domain'].unique().tolist()[:10] 
    
    results = []
    for domain in domains:
        print(f"Scanare de bază: {domain}")
        try:
            r = requests.get(f"http://{domain}", timeout=5)
            html = r.text.lower()
            
            techs = []
            if "wp-content" in html: techs.append("WordPress")
            if "shopify" in html: techs.append("Shopify")
            if "google-analytics" in html: techs.append("Google Analytics")
            
            results.append({"domain": domain, "techs": techs})
        except:
            results.append({"domain": domain, "techs": ["Error/Timeout"]})
            
    with open('output_basic.json', 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    scanner()