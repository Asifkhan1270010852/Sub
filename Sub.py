import requests
import subprocess
import json
import os
import argparse
from tqdm import tqdm
from dotenv import load_dotenv
from censys.search import CensysCerts
from censys.common.exceptions import CensysUnauthorizedException

load_dotenv()

# Load all API keys
VT_API_KEY = os.getenv("VT_API_KEY")
ST_API_KEY = os.getenv("ST_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")

def run_assetfinder(domain):
    try:
        output = subprocess.check_output(['assetfinder', '--subs-only', domain])
        return output.decode().splitlines()
    except:
        return []

def run_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)
        data = response.json()
        subdomains = set()
        for entry in data:
            names = entry['name_value'].split('\n')
            for name in names:
                if "*" not in name:
                    subdomains.add(name.strip())
        return list(subdomains)
    except:
        return []

def run_subfinder(domain):
    try:
        output = subprocess.check_output(['subfinder', '-d', domain, '-silent', '-all'])
        return output.decode().splitlines()
    except:
        return []

def run_amass(domain):
    try:
        output = subprocess.check_output(['amass', 'enum', '-passive', '-d', domain])
        return output.decode().splitlines()
    except:
        return []

def run_virustotal(domain):
    subdomains = set()
    if not VT_API_KEY:
        return []
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100"
        headers = {"x-apikey": VT_API_KEY}
        while url:
            res = requests.get(url, headers=headers)
            data = res.json()
            for item in data.get("data", []):
                subdomains.add(item["id"])
            url = data.get("links", {}).get("next")
        return list(subdomains)
    except:
        return []

def run_securitytrails(domain):
    subdomains = set()
    if not ST_API_KEY:
        return []
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": ST_API_KEY}
        res = requests.get(url, headers=headers)
        data = res.json()
        for sub in data.get("subdomains", []):
            subdomains.add(f"{sub}.{domain}")
        return list(subdomains)
    except:
        return []

def run_shodan(domain):
    subdomains = set()
    if not SHODAN_API_KEY:
        return []
    try:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        data = response.json()
        for item in data.get("subdomains", []):
            subdomains.add(f"{item}.{domain}")
        return list(subdomains)
    except:
        return []

def run_censys(domain):
    subdomains = set()
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return []
    try:
        certs = CensysCerts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        query = f"parsed.names: {domain}"
        results = certs.search(query, fields=["parsed.names"], max_records=100)
        for r in results:
            for name in r.get("parsed.names", []):
                if name.endswith(domain) and "*" not in name:
                    subdomains.add(name)
        return list(subdomains)
    except CensysUnauthorizedException:
        print("[!] Censys API Unauthorized. Check your credentials.")
        return []
    except:
        return []

def save_output(subdomains, output_file, json_output=False):
    if json_output:
        with open(output_file, 'w') as f:
            json.dump({"subdomains": subdomains}, f, indent=2)
    else:
        with open(output_file, 'w') as f:
            for sub in subdomains:
                f.write(sub + '\n')

def main():
    parser = argparse.ArgumentParser(description="Python Subdomain Finder Tool (with All APIs)")
    parser.add_argument("domain", help="Target domain (example.com)")
    parser.add_argument("-o", "--output", default="subdomains.txt", help="Output file name")
    parser.add_argument("-j", "--json", action="store_true", help="Save output in JSON format")
    parser.add_argument("-f", "--filter", action="store_true", help="Filter only valid subdomains of target domain")

    args = parser.parse_args()
    domain = args.domain

    print(f"\n🔍 Finding subdomains for: {domain}\n")

    all_subdomains = []

    for name, func in tqdm([
        ("Assetfinder", run_assetfinder),
        ("crt.sh", run_crtsh),
        ("Subfinder", run_subfinder),
        ("Amass", run_amass),
        ("VirusTotal", run_virustotal),
        ("SecurityTrails", run_securitytrails),
        ("Shodan", run_shodan),
        ("Censys", run_censys)
    ]):
        result = func(domain)
        print(f"[+] {name}: {len(result)} found")
        all_subdomains.extend(result)

    # Deduplicate
    unique_subdomains = sorted(set(all_subdomains))

    # Optional filtering
    if args.filter:
        unique_subdomains = [s for s in unique_subdomains if s.endswith(f".{domain}")]

    print(f"\n✅ Total Unique Subdomains: {len(unique_subdomains)}")

    # Save output
    save_output(unique_subdomains, args.output, json_output=args.json)
    print(f"📁 Output saved to: {args.output}\n")

if __name__ == "__main__":
    main()
