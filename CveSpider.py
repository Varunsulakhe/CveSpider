import os
import argparse
import socket
import requests
import sys
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

# Load environment variables from .env file
load_dotenv()

# Initialize Rich Console
console = Console()

# Function to display a fancy banner
def banner(output_file=None):
    banner_text = "[bold green]CVE Spidering Tool[/bold green]\n" \
                  "[bold yellow]Author:[/bold yellow] IamGr000t\n" \
                  "[bold cyan]Hunting CVEs Made Easy[/bold cyan]"
    panel = Panel.fit(
        banner_text,
        title="[bold blue]Welcome[/bold blue]",
        border_style="bold magenta"
    )
    if output_file:
        with console.capture() as capture:
            console.print(panel)
        captured_output = capture.get()
        output_file.write(captured_output + "\n")  # Write to file
    else:
        console.print(panel)  # Print to the console

# Function to resolve a domain to an IP address
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        console.print(f"[bold red][!] Unable to resolve domain: {domain}[/bold red]") 
        sys.exit(1)

# Function to fetch data from Shodan InternetDB API
def fetch_data(ip):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        console.print(f"[bold red][!] Error fetching data: {e}[/bold red]")
        return {}

# Function to fetch CVE base scores from NVD
def get_base_score(cve_id):
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return "Error fetching data", url
        
        soup = BeautifulSoup(response.text, 'html.parser')
        base_score_section = soup.find('a', {'data-testid': 'vuln-cvss3-panel-score'})
        
        if base_score_section:
            return base_score_section.text.strip(), url
        else:
            return "[bold red]Not Found[/bold red]", url
    except Exception as e:
        return f"Error fetching base score: {str(e)}", url

# Function to display CVEs with base scores
def display_cves(cves, output_file=None):
    output = "\n[bold green]Vulnerabilities (CVEs):[/bold green]\n\n"
    
    if not cves:
        output += "N/A\n"
    else:
        with ThreadPoolExecutor() as executor:
            results = executor.map(get_base_score, cves)
        
        for cve, (base_score, url) in zip(cves, results):
            output += f" -> | {cve} \t| {base_score} \t| [link={url}]{url}[/link]\t|\n"
    
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

# Function to display open ports
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
        console.print(f"[bold yellow][+] Resolving domain {target} to IP...[/bold yellow]")
        target = resolve_domain(target)

    console.print(f"[bold cyan][+] Fetching data for IP: {target}...[bold cyan]")
    data = fetch_data(target)

    display_hostnames(data.get("hostnames", []), output_file)
    display_ports(data.get("ports", []), output_file)
    display_cves(data.get("vulns", []), output_file)

    if output_file:
        output_file.close()

if __name__ == "__main__":
    main()
