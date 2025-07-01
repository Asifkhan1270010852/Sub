#!/bin/bash

echo "🔧 Starting Subdomain Tools Installation..."

# Update & install dependencies
sudo apt update -y
sudo apt install git curl python3 python3-pip -y

# Install Go (if not present)
if ! command -v go &> /dev/null; then
  echo "📦 Installing GoLang..."
  wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  source ~/.bashrc
fi

# Setup Go path
mkdir -p ~/go/bin
export PATH=$PATH:~/go/bin

# Install Go-based tools
echo "🚀 Installing Assetfinder..."
go install github.com/tomnomnom/assetfinder@latest

echo "🚀 Installing Subfinder..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "🚀 Installing Amass..."
go install github.com/owasp-amass/amass/v4/...@latest

# Install Python libraries for APIs
pip install requests

# Setup directory for API tools
mkdir -p ~/subdomain_apis
cd ~/subdomain_apis

# Save Python scripts for API-based recon

# 🔍 crt.sh fetcher
cat << 'EOF' > crtsh.py
import requests, sys
domain = sys.argv[1]
url = f"https://crt.sh/?q=%25.{domain}&output=json"
r = requests.get(url)
for entry in r.json():
    for name in entry['name_value'].split('\n'):
        print(name.strip())
EOF

# 🔍 VirusTotal (Needs API key)
cat << 'EOF' > virustotal.py
import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
headers = {"x-apikey": API_KEY}
r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", headers=headers)
for item in r.json().get('data', []):
    print(item['id'])
EOF

# 🔍 SecurityTrails (Needs API key)
cat << 'EOF' > securitytrails.py
import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
r = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", headers={"APIKEY": API_KEY})
for sub in r.json().get("subdomains", []):
    print(f"{sub}.{domain}")
EOF

# 🔍 Shodan (Needs API key)
cat << 'EOF' > shodan.py
import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
url = f"https://api.shodan.io/dns/domain/{domain}?key={API_KEY}"
r = requests.get(url)
for sub in r.json().get("subdomains", []):
    print(f"{sub}.{domain}")
EOF

# 🔍 Censys (Needs API ID + Secret)
cat << 'EOF' > censys.py
import requests, sys, base64
domain = sys.argv[1]
UID = "PASTE_UID"
SECRET = "PASTE_SECRET"
auth = base64.b64encode(f"{UID}:{SECRET}".encode()).decode()
headers = {"Authorization": f"Basic {auth}"}
r = requests.get(f"https://search.censys.io/api/v2/domains/{domain}/subdomains", headers=headers)
for sub in r.json().get("result", {}).get("subdomains", []):
    print(f"{sub}.{domain}")
EOF

# Make scripts executable
chmod +x *.py

echo -e "\n✅ All tools installed!"
echo "📦 CLI tools: assetfinder, subfinder, amass"
echo "📜 API scripts saved in: ~/subdomain_apis"
echo "⚠️ NOTE: Paste your API keys in scripts before use"
