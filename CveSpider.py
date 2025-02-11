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

# Fetch API Keys from Environment
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
    except requests.HTTPError as e:
        if response.status_code == 403:
            console.print("[bold red][!] Shodan API access denied. Upgrade your plan or check your API key.[/bold red]")
        elif response.status_code == 401:
            console.print("[bold red][!] Invalid Shodan API key. Please check your key.[/bold red]")
        else:
            console.print(f"[bold red][!] Error fetching Shodan data: {e}[/bold red]")
        return {}


# Function to fetch VirusTotal IP Reputation
def fetch_virustotal_data(ip):
    if not VIRUSTOTAL_API_KEY:
        console.print("[bold red][!] VirusTotal API key is missing. Skipping VirusTotal scan.[/bold red]")
        return "Skipped", ""

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 401:
            console.print("[bold red][!] Invalid VirusTotal API key. Please check your API key.[/bold red]")
            return "Unauthorized (Invalid API Key)", url
        response.raise_for_status()
        
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        return f"Malicious: {malicious}, Suspicious: {suspicious}", url
    except requests.RequestException as e:
        return f"Error: {str(e)}", url

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
    
    console.print(f"[bold cyan][+] Fetching data for IP: {target}...[bold cyan]")
    
    # Fetch data from Shodan
    shodan_data = fetch_data(target)
    
    # Fetch VirusTotal Data
    vt_result, vt_url = fetch_virustotal_data(target)
    console.print(f"\n[bold green]VirusTotal Report:[/bold green] {vt_result} | [link={vt_url}]{vt_url}[/link]")

    # If output file is provided, write results
    if output_file:
        output_file.write(f"Resolved IP: {target}\n")
        output_file.write(f"VirusTotal Report: {vt_result} | {vt_url}\n")
        output_file.close()

if __name__ == "__main__":
    main()
