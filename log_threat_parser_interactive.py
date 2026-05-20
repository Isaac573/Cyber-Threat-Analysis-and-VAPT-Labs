import re
from collections import Counter
from datetime import datetime

# Function to generate Apache-style timestamp
def apache_time():
    return datetime.now().strftime("[%d/%b/%Y:%H:%M:%S]")

def parse_logs(target_ip):
    print("[*] Initiating Threat Intelligence Log Parser Simulation...")
    
    # Simulated Web Server Log Data (with dynamic timestamps)
    log_data = [
        f"{target_ip} - - {apache_time()} \"POST /login HTTP/1.1\" 401 234",
        f"{target_ip} - - {apache_time()} \"POST /login HTTP/1.1\" 401 234",
        f"{target_ip} - - {apache_time()} \"POST /login HTTP/1.1\" 401 234",
        f"{target_ip} - - {apache_time()} \"GET /index.php?id=1' OR 1=1 HTTP/1.1\" 200 4523",
        f"{target_ip} - - {apache_time()} \"GET /assets/logo.png HTTP/1.1\" 200 12344",
        f"{target_ip} - - {apache_time()} \"GET /etc/passwd HTTP/1.1\" 403 892"
    ]
    
    # Regex patterns for tracking malicious activity
    failed_login_pattern = r'"POST /login.*" 401'
    sqli_pattern = r"OR 1=1|'|--"
    path_traversal_pattern = r"/etc/passwd|win.ini"

    failed_logins = []
    suspicious_ips = set()

    for entry in log_data:
        ip = target_ip  # already injected
        
        # 1. Detect Potential Brute Force
        if re.search(failed_login_pattern, entry):
            failed_logins.append(ip)
            
        # 2. Detect Web Application Attacks
        if re.search(sqli_pattern, entry) or re.search(path_traversal_pattern, entry):
            suspicious_ips.add(ip)
            print(f"[ALERT] Malicious Web Exploit Pattern Detected from Target IP: {ip}")

    # Process Brute Force Thresholds
    ip_counts = Counter(failed_logins)
    for ip, count in ip_counts.items():
        if count >= 3:
            print(f"[ALERT] Potential Auth Brute-Force Detected from IP: {ip} ({count} failed attempts)")

if __name__ == "__main__":
    target_ip = input("Enter TARGET-IP: ")
    parse_logs(target_ip)
