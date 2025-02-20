# Automated_webapp_recon
An automated Web application reconnaissance tool

This was created as a part of my VAPT project, i hope to i prove it, and make it a more in-depth tool
🚀 Features
🔍 Subdomain Enumeration – Finds subdomains using brute-force techniques.
🌐 DNS & WHOIS Lookups – Retrieves DNS records and WHOIS registration data.
🛠 Technology Detection – Identifies web technologies from HTTP headers.
📡 Network Footprinting – Performs reverse IP lookup and ASN retrieval.
🕵️ OSINT (Open-Source Intelligence) – Searches for social media accounts linked to the target.
📊 Rich Console Output – Displays results in a structured format with Rich CLI styling.
💾 JSON Output – Saves findings to a recon_results.json file.
⚙️ Installation
bash
Copy
Edit
git clone https://github.com/yourusername/web-recon-tool.git
cd web-recon-tool
pip install -r requirements.txt
🔧 Usage
bash
Copy
Edit
python recon.py
Enter the target domain when prompted. The tool will perform reconnaissance and save results in recon_results.json.

🏗 Dependencies
requests
concurrent.futures
dns.resolver
whois
socket
beautifulsoup4
tqdm
rich
