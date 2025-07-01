import os
import subprocess
import sys
from time import sleep
from colorama import Fore, Style, init
from pyfiglet import figlet_format

init(autoreset=True)

def run_cmd(cmd, desc=""):
    print(Fore.YELLOW + f"🔧 {desc}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(Fore.RED + "❌ Failed: " + cmd)
        sys.exit(1)

def print_ascii_banner():
    banner_text = figlet_format("ASIF KHAN", font="slant")
    print(Fore.BLUE + Style.BRIGHT + banner_text)

def print_banner():
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════╗
║     🚀 Subdomain Toolkit Installer (Python)    ║
╚═══════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def install_dependencies():
    print(Fore.GREEN + "🔹 Step 1: Installing system dependencies...")
    run_cmd("sudo apt update -y", "Updating system")
    run_cmd("sudo apt install git curl python3 python3-pip -y", "Installing Git, Curl, Python3")

def install_golang():
    print(Fore.GREEN + "🔹 Step 2: Checking & Installing GoLang...")
    if subprocess.call("command -v go", shell=True) != 0:
        run_cmd("wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz", "Downloading GoLang")
        run_cmd("sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz", "Extracting Go")
        bashrc = os.path.expanduser("~/.bashrc")
        with open(bashrc, "a") as f:
            f.write('\nexport PATH=$PATH:/usr/local/go/bin:$HOME/go/bin\n')
        print(Fore.YELLOW + "🔁 Restart your terminal or run `source ~/.bashrc` after this script.")
    os.makedirs(os.path.expanduser("~/go/bin"), exist_ok=True)

def install_go_tools():
    print(Fore.GREEN + "🔹 Step 3: Installing Go-based Tools...")
    tools = {
        "Assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "Subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "Amass": "go install github.com/owasp-amass/amass/v4/...@latest"
    }
    for name, cmd in tools.items():
        run_cmd(cmd, f"Installing {name}")

def create_api_scripts():
    print(Fore.GREEN + "🔹 Step 4: Creating API Recon Scripts...")
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
        path = os.path.join(api_dir, name)
        with open(path, "w") as f:
            f.write(code.strip())
        os.chmod(path, 0o755)
        print(Fore.CYAN + f"✅ Created: {name}")

def show_summary():
    print(f"""{Fore.MAGENTA}
╔════════════════════════════════════╗
║   ✅ All tools installed!           ║
╠════════════════════════════════════╣
║ 🔹 Go tools: assetfinder, subfinder, amass
║ 🔹 API scripts: ~/subdomain_apis
║ 🔹 Note: Paste your API keys before running scripts
╚════════════════════════════════════╝
""")

def main():
    print_ascii_banner()
    print_banner()
    install_dependencies()
    install_golang()
    install_go_tools()
    create_api_scripts()
    show_summary()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(Fore.RED + "❗ Please run this script with: sudo python3 installer.py")
        sys.exit(1)
    main()
