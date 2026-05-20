import re
from collections import Counter

# Simulated Web Server Log Data (Apache/Nginx style)
log_data = [
    '[TARGET-IP] - - [15/May/2026:13:45:02] "POST /login HTTP/1.1" 401 234',
    '[TARGET-IP] - - [15/May/2026:13:45:05] "POST /login HTTP/1.1" 401 234',
    '[TARGET-IP] - - [15/May/2026:13:45:08] "POST /login HTTP/1.1" 401 234',
    '[TARGET-IP] - - [15/May/2026:13:46:12] "GET /index.php?id=1\'%20OR%201=1 HTTP/1.1" 200 4523',
    '[TARGET-IP] - - [15/May/2026:13:47:00] "GET /assets/logo.png HTTP/1.1" 200 12344',
    '[TARGET-IP] - - [15/May/2026:13:47:15] "GET /etc/passwd HTTP/1.1" 403 892'
]

def parse_logs():
    print("[*] Initiating Threat Intelligence Log Parser Simulation...")
    
    # Regex patterns for tracking malicious activity
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    failed_login_pattern = r'"POST /login.*" 401'
    sqli_pattern = r"OR%201=1|'|--"
    path_traversal_pattern = r"/etc/passwd|win.ini"

    failed_logins = []
    suspicious_ips = set()

    for entry in log_data:
        ip = re.search(ip_pattern, entry).group()
        
        # 1. Detect Potential Brute Force (Multiple 401 Unauthorised status codes)
        if re.search(failed_login_pattern, entry):
            failed_logins.append(ip)
            
        # 2. Detect Web Application Attacks (SQL Injection / Path Traversal)
        if re.search(sqli_pattern, entry) or re.search(path_traversal_pattern, entry):
            suspicious_ips.add(ip)
            print(f"[ALERT] Malicious Web Exploit Pattern Detected from Target IP: {ip}")

    # Process Brute Force Thresholds
    ip_counts = Counter(failed_logins)
    for ip, count in ip_counts.items():
        if count >= 3:
            print(f"[ALERT] Potential Auth Brute-Force Detected from IP: {ip} ({count} failed attempts)")

if __name__ == "__main__":
    parse_logs()
