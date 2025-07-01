import os
import subprocess
import sys
import argparse
from colorama import Fore, Style, init
from pyfiglet import figlet_format

init(autoreset=True)

TOOLS = {
    "Assetfinder": "assetfinder",
    "Subfinder": "subfinder",
    "Amass": "amass"
}

def run_cmd(cmd, desc=""):
    print(Fore.YELLOW + f"🔧 {desc}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(Fore.RED + "❌ Failed: " + cmd)
        sys.exit(1)

def is_installed(command):
    return subprocess.call(f"command -v {command}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

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

def print_help():
    help_text = f"""
{Fore.GREEN}Usage: sudo python3 installer.py [--install | --update | --help]

Options:
  --install       Install the toolkit (default)
  --update        Update Go tools only (if already installed)
  --help          Show this help message

API Key Files:
  🔑 Paste your API keys in scripts inside: ~/subdomain_apis/
    - virustotal.py
    - shodan.py
    - securitytrails.py
    - censys.py
"""
    print(help_text)

def install_dependencies():
    print(Fore.GREEN + "🔹 Installing system dependencies...")
    run_cmd("sudo apt update -y", "Updating system")
    run_cmd("sudo apt install git curl python3 python3-pip -y", "Installing Git, Curl, Python3")

def install_golang():
    print(Fore.GREEN + "🔹 Checking & Installing GoLang...")
    if not is_installed("go"):
        run_cmd("wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz", "Downloading GoLang")
        run_cmd("sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz", "Extracting Go")
        bashrc = os.path.expanduser("~/.bashrc")
        with open(bashrc, "a") as f:
            f.write('\nexport PATH=$PATH:/usr/local/go/bin:$HOME/go/bin\n')
        print(Fore.YELLOW + "🔁 Restart your terminal or run `source ~/.bashrc` after this script.")
    os.makedirs(os.path.expanduser("~/go/bin"), exist_ok=True)

def install_go_tools():
    print(Fore.GREEN + "🔹 Installing Go-based Tools...")
    for name, binary in TOOLS.items():
        if not is_installed(binary):
            cmd = f"go install github.com/{'projectdiscovery/' + binary + '/v2/cmd/' + binary if 'subfinder' in binary else ('owasp-amass/amass/v4/...@latest' if 'amass' in binary else 'tomnomnom/' + binary + '@latest')}"
            run_cmd(cmd, f"Installing {name}")
        else:
            print(Fore.CYAN + f"✅ {name} already installed, skipping...")

def create_api_scripts():
    print(Fore.GREEN + "🔹 Creating API Recon Scripts...")
    api_dir = os.path.expanduser("~/subdomain_apis")
    os.makedirs(api_dir, exist_ok=True)
    scripts = {
        "crtsh.py": '''import requests, sys
domain = sys.argv[1]
url = f\"https://crt.sh/?q=%25.{domain}&output=json\"
r = requests.get(url)
for entry in r.json():
    for name in entry['name_value'].split('\\n'):
        print(name.strip())''',
        "virustotal.py": '''import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
headers = {"x-apikey": API_KEY}
r = requests.get(f\"https://www.virustotal.com/api/v3/domains/{domain}/subdomains\", headers=headers)
for item in r.json().get('data', []):
    print(item['id'])''',
        "securitytrails.py": '''import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
r = requests.get(f\"https://api.securitytrails.com/v1/domain/{domain}/subdomains\", headers={"APIKEY": API_KEY})
for sub in r.json().get("subdomains", []):
    print(f"{sub}.{domain}")''',
        "shodan.py": '''import requests, sys
domain = sys.argv[1]
API_KEY = "PASTE_YOUR_API_KEY"
url = f\"https://api.shodan.io/dns/domain/{domain}?key={API_KEY}\"
r = requests.get(url)
for sub in r.json().get("subdomains", []):
    print(f"{sub}.{domain}")''',
        "censys.py": '''import requests, sys, base64
domain = sys.argv[1]
UID = "PASTE_UID"
SECRET = "PASTE_SECRET"
auth = base64.b64encode(f"{UID}:{SECRET}".encode()).decode()
headers = {"Authorization": f"Basic {auth}"}
r = requests.get(f\"https://search.censys.io/api/v2/domains/{domain}/subdomains\", headers=headers)
for sub in r.json().get("result", {}).get("subdomains", []):
    print(f"{sub}.{domain}")'''
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
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--help", action="store_true")
    args = parser.parse_args()

    print_ascii_banner()
    print_banner()

    if args.help:
        print_help()
        return
    elif args.update:
        install_go_tools()
        show_summary()
        return

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
