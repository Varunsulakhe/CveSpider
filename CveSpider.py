import os
import argparse
import socket
import requests
import sys
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from concurrent.futures import ThreadPoolExecutor

# Load environment variables from .env file
load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VULDB_API_KEY = os.getenv("VULDB_API_KEY")

# Initialize Rich Console
console = Console()

# Function to display a fancy banner
def banner(output_file=None):
    banner_text = """
    [bold green]CVE Spidering Tool[/bold green]
    [bold yellow]Author:[/bold yellow] iamgr00t
    [bold cyan]Hunting CVEs Made Easy[/bold cyan]
    """
    panel = Panel.fit(
        banner_text.strip(),
        title="[bold blue]Welcome[/bold blue]",
        border_style="bold magenta"
    )

    if output_file:
        with console.capture() as capture:
            console.print(panel)
        captured_output = capture.get()
        output_file.write(captured_output + "\n")  # Write to file
    else:
        console.print(panel)

# Function to resolve a domain to an IP address
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        console.print(f"[bold red][!] Unable to resolve domain: {domain}[/bold red]")
        sys.exit(1)

# Function to fetch data from Shodan API
def fetch_data(ip):
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        console.print(f"[bold red][!] Error fetching Shodan data: {e}[/bold red]")
        return {}

# Function to fetch VirusTotal IP Reputation
def fetch_virustotal_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return f"Malicious: {malicious}, Suspicious: {suspicious}", url
    except requests.RequestException as e:
        return f"Error: {str(e)}", url

# Function to fetch CVE base scores from VULNDB API
def get_vuldb_cve(cve_id):
    url = "https://vuldb.com/?api"
    payload = {"apikey": VULDB_API_KEY, "search": cve_id}
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        if "result" in data and isinstance(data["result"], list):
            base_score = data["result"][0].get("cvss", "Not Found")
            return base_score, url
        else:
            return "Not Found", url
    except requests.RequestException as e:
        return f"Error: {str(e)}", url

# Function to display CVEs with base scores
def display_cves(cves, output_file=None):
    output = "\n[bold green]Vulnerabilities (CVEs):[/bold green]\n"
    if not cves:
        output += "N/A\n"
    else:
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(get_vuldb_cve, cves))
        for cve, (base_score, url) in zip(cves, results):
            output += f" -> | {cve} | {base_score} | [link={url}]{url}[/link] |\n"
    
    if output_file:
        output_file.write(output)
    else:
        console.print(output)

# Function to display hostnames
def display_hostnames(hostnames, output_file=None):
    output = "\n[bold green]Hostnames:[/bold green]\n"
    output += "\n".join(f" -> {hostname}" for hostname in hostnames) if hostnames else "N/A\n"
    if output_file:
        output_file.write(output)
    else:
        console.print(output)

# Function to display ports
def display_ports(ports, output_file=None):
    output = "\n[bold green]Open Ports:[/bold green]\n"
    output += "\n".join(f" -> {port}" for port in ports) if ports else "N/A\n"
    if output_file:
        output_file.write(output)
    else:
        console.print(output)

# Main function
def main():
    parser = argparse.ArgumentParser(description="Ultimate CVE Hunting Tool")
    parser.add_argument("-d", "--domain", help="IP address or domain to scan")
    parser.add_argument("-o", "--output", help="Output file to store results", type=str)
    args = parser.parse_args()
    
    output_file = open(args.output, "w", encoding="utf-8") if args.output else None
    banner(output_file)
    
    target = args.domain or sys.stdin.read().strip()
    if not target:
        console.print("[bold red][!] No input provided via pipe or argument.[/bold red]")
        sys.exit(1)
    
    if not target.replace(".", "").isdigit():
        console.print(f"[bold yellow][+] Resolving domain {target} to IP...[bold yellow]")
        target = resolve_domain(target)
    
    data = fetch_data(target)
    vt_result, vt_url = fetch_virustotal_data(target)
    console.print(f"\n[bold green]VirusTotal Report:[/bold green] {vt_result} | [link={vt_url}]{vt_url}[/link]")

if __name__ == "__main__":
    main()
