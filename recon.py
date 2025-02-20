import requests
import concurrent.futures
import dns.resolver
import socket
import whois
import json
import re
from bs4 import BeautifulSoup
from tqdm import tqdm
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Global variable to store results
results = {"subdomains": [], "dns": {}, "whois": {}, "technology": {}, "network": {}, "osint": {}}

### -------------------- 1️⃣ SUBDOMAIN ENUMERATION -------------------- ###
def brute_force_subdomains(domain, wordlist="/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt", threads=50):
    console.print("[cyan][*] Performing Subdomain Enumeration...[/cyan]")

    def check_subdomain(sub):
        url = f"http://{sub}.{domain}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code < 400:
                results["subdomains"].append(url)
        except requests.ConnectionError:
            pass

    try:
        with open(wordlist, "r") as file:
            subdomains = file.read().splitlines()

        with tqdm(total=len(subdomains), desc="Enumerating Subdomains", ncols=80) as progress:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
                for future in concurrent.futures.as_completed(futures):
                    progress.update(1)
    
    except FileNotFoundError:
        console.print("[red][!] Wordlist file not found.[/red]")

### -------------------- 2️⃣ DNS & WHOIS LOOKUPS -------------------- ###
def get_dns_info(domain):
    console.print("[cyan][*] Performing DNS Lookup...[/cyan]")
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT"]

    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            results["dns"][record] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            pass

def get_whois_info(domain):
    console.print("[cyan][*] Fetching WHOIS Information...[/cyan]")
    try:
        whois_data = whois.whois(domain)
        results["whois"] = {
            "registrar": whois_data.registrar,
            "creation_date": str(whois_data.creation_date),
            "expiration_date": str(whois_data.expiration_date),
            "name_servers": whois_data.name_servers,
        }
    except Exception:
        console.print("[red][!] WHOIS lookup failed.[/red]")

### -------------------- 3️⃣ TECHNOLOGY DETECTION -------------------- ###
def detect_technology(domain):
    console.print("[cyan][*] Detecting Technologies...[/cyan]")
    url = f"http://{domain}"

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        server = headers.get("Server", "Unknown")
        powered_by = headers.get("X-Powered-By", "Unknown")

        results["technology"] = {
            "server": server,
            "powered_by": powered_by
        }
    except requests.exceptions.RequestException:
        console.print("[red][!] Technology detection failed.[/red]")

### -------------------- 4️⃣ NETWORK FOOTPRINTING -------------------- ###
def get_reverse_ip_lookup(domain):
    console.print("[cyan][*] Performing Reverse IP Lookup...[/cyan]")
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if response.status_code == 200:
            results["network"]["reverse_ip"] = response.text.split("\n")
    except Exception:
        console.print("[red][!] Reverse IP lookup failed.[/red]")

def get_asn_info(domain):
    console.print("[cyan][*] Fetching ASN Information...[/cyan]")
    try:
        response = requests.get(f"https://api.hackertarget.com/aslookup/?q={domain}")
        if response.status_code == 200:
            results["network"]["asn_info"] = response.text
    except Exception:
        console.print("[red][!] ASN lookup failed.[/red]")

### -------------------- 5️⃣ OSINT & SOCIAL MEDIA -------------------- ###
def find_social_media_links(domain):
    console.print("[cyan][*] Searching for Social Media Accounts...[/cyan]")
    social_platforms = ["facebook.com", "twitter.com", "linkedin.com", "github.com"]
    found_profiles = []

    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(f"https://www.google.com/search?q=site:{domain}+social", headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")
        for a in soup.find_all("a", href=True):
            if any(platform in a["href"] for platform in social_platforms):
                found_profiles.append(a["href"])

        results["osint"]["social_media"] = found_profiles

    except requests.exceptions.RequestException:
        console.print("[red][!] Social media search failed.[/red]")

### -------------------- DISPLAY RESULTS -------------------- ###
def display_results():
    console.print(Panel("[bold green]Reconnaissance Complete![/bold green]", expand=False))

    # Subdomains
    table = Table(title="Subdomains Found", show_header=True, header_style="bold cyan")
    table.add_column("Subdomain", style="dim")
    for sub in results["subdomains"]:
        table.add_row(sub)
    console.print(table)

    # DNS Records
    table = Table(title="DNS Records", show_header=True, header_style="bold yellow")
    table.add_column("Record Type", style="bold")
    table.add_column("Value")
    for record, values in results["dns"].items():
        table.add_row(record, "\n".join(values))
    console.print(table)

    # WHOIS
    table = Table(title="WHOIS Information", show_header=True, header_style="bold magenta")
    table.add_column("Attribute", style="bold")
    table.add_column("Value")
    for key, value in results["whois"].items():
        table.add_row(key, str(value))
    console.print(table)

    # Technology Stack
    table = Table(title="Technology Stack", show_header=True, header_style="bold blue")
    table.add_column("Attribute", style="bold")
    table.add_column("Value")
    for key, value in results["technology"].items():
        table.add_row(key, value)
    console.print(table)

### -------------------- RUN RECON -------------------- ###
def save_results():
    with open("recon_results.json", "w") as outfile:
        json.dump(results, outfile, indent=4)
    console.print("[green][✔] Results saved to recon_results.json[/green]")

def run_recon(target, threads=10):
    console.print(f"[bold cyan][*] Running reconnaissance on {target}...[/bold cyan]")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(brute_force_subdomains, target, threads=threads),
            executor.submit(get_dns_info, target),
            executor.submit(get_whois_info, target),
            executor.submit(detect_technology, target),
            executor.submit(get_reverse_ip_lookup, target),
            executor.submit(get_asn_info, target),
            executor.submit(find_social_media_links, target),
        ]

        concurrent.futures.wait(futures)

    display_results()
    save_results()

# Example usage
if __name__ == "__main__":
    target_domain = input("Enter target domain: ")
    run_recon(target_domain)

