import requests
import json
import sys

def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url)
        data = response.json()

        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split("\n"):
                if domain in sub:
                    subdomains.add(sub.strip())

        return sorted(subdomains)
    except Exception as e:
        print(f"[!] Error: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 crt_subdomain_clean.py example.com")
        sys.exit(1)

    domain = sys.argv[1]
    subdomains = get_subdomains(domain)

    print("\n[+] Found Subdomains:")
    for sub in subdomains:
        print(sub)
