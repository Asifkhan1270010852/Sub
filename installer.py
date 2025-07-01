import os
import subprocess
import sys

def run_cmd(cmd):
    print(f"📦 Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def install_dependencies():
    print("🔧 Installing system dependencies...")
    run_cmd("sudo apt update -y")
    run_cmd("sudo apt install git curl python3 python3-pip -y")

def install_golang():
    if subprocess.call("command -v go", shell=True) != 0:
        print("📦 Installing GoLang...")
        run_cmd("wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz")
        run_cmd("sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz")
        bashrc = os.path.expanduser("~/.bashrc")
        with open(bashrc, "a") as f:
            f.write('\nexport PATH=$PATH:/usr/local/go/bin:$HOME/go/bin\n')
        run_cmd("source ~/.bashrc")
    os.makedirs(os.path.expanduser("~/go/bin"), exist_ok=True)
    os.environ["PATH"] += ":" + os.path.expanduser("~/go/bin")

def install_go_tools():
    print("🚀 Installing Go-based tools...")
    run_cmd("go install github.com/tomnomnom/assetfinder@latest")
    run_cmd("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    run_cmd("go install github.com/owasp-amass/amass/v4/...@latest")

def install_python_libs():
    print("📦 Installing Python libraries...")
    run_cmd("pip install requests")

def create_api_scripts():
    print("📝 Creating API-based recon scripts...")
    api_dir = os.path.expanduser("~/subdomain_apis")
    os.makedirs(api_dir, exist_ok=True)

    scripts = {
        "crtsh.py": '''
import requests, sys
domain = sys.argv[1]
url = f"https://crt.sh/?q=%25.{domain}&output=json"
r = requests.get(url)
for entry in r.json():
    for name in entry['name_value'].split('\\n'):
        print(name.strip())
''',

        "virustotal.py": '''
import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
headers = {"x-apikey": API_KEY}
r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", headers=headers)
for item in r.json().get('data', []):
    print(item['id'])
''',

        "securitytrails.py": '''
import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
r = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", headers={"APIKEY": API_KEY})
for sub in r.json().get("subdomains", []):
    print(f"{sub}.{domain}")
''',

        "shodan.py": '''
import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
url = f"https://api.shodan.io/dns/domain/{domain}?key={API_KEY}"
r = requests.get(url)
for sub in r.json().get("subdomains", []):
    print(f"{sub}.{domain}")
''',

        "censys.py": '''
import requests, sys, base64
domain = sys.argv[1]
UID = "PASTE_UID"
SECRET = "PASTE_SECRET"
auth = base64.b64encode(f"{UID}:{SECRET}".encode()).decode()
headers = {"Authorization": f"Basic {auth}"}
r = requests.get(f"https://search.censys.io/api/v2/domains/{domain}/subdomains", headers=headers)
for sub in r.json().get("result", {}).get("subdomains", []):
    print(f"{sub}.{domain}")
'''
    }

    for name, code in scripts.items():
        script_path = os.path.join(api_dir, name)
        with open(script_path, "w") as f:
            f.write(code.strip())
        os.chmod(script_path, 0o755)

def main():
    print("🚀 Starting Python-based Subdomain Tool Installer...")
    install_dependencies()
    install_golang()
    install_go_tools()
    install_python_libs()
    create_api_scripts()

    print("\n✅ All tools installed!")
    print("📦 CLI tools: assetfinder, subfinder, amass")
    print("📜 API scripts saved in: ~/subdomain_apis")
    print("⚠️ NOTE: Paste your API keys in the scripts before using them.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ Please run this script using: sudo python3 installer.py")
        sys.exit(1)
    main()
