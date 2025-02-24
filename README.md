# WebPenAut - Automated Web Reconnaissance  

**WebPenAut** is an automated web reconnaissance tool for penetration testers. It performs **subdomain enumeration, port scanning, service detection, and directory brute-forcing**, storing results in JSON format.  

## 🚀 Features  
- **Subdomain Enumeration** (Recursive)  
- **Port Scanning & Service Detection** (Nmap)  
- **Zone Transfer Analysis**  
- **Directory Bruteforcing** (Gobuster)  
- **Live Subdomain Checking** (HTTPX)
- **DNS & WHOIS Lookups**  
- **Service Detection & Port Scanning** (Nmap)  
- **Technology Fingerprinting** (WhatWeb)  
- **Web Application Firewall Detection** (wafw00f)  
- **Reverse IP Lookup & ASN Info**  
 

## 🛠️ Installation  
```bash
git clone https://github.com/rocky1505/Automated_webapp_recon.git  
cd Automated_webapp_recon
```
## USAGE
```bash
python3 webpenaut.py -u <target_domain>       
python3 webpenaut.py -r recon -u <target_domain>  # for specifically recon alone
```
⚠️ Disclaimer
Entire run may take from 5 to 10 mins
