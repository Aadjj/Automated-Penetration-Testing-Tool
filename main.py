import nmap
import requests
import json
import os
import socket
import concurrent.futures
import time

# API URLs
VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"
EXPLOIT_DB_URL = "https://www.exploit-db.com/search?cve="

# Banners
BANNER = """
🔍 Automated Penetration Testing Tool
--------------------------------------
🛠 Scanning & Exploiting Target Systems
"""


def get_banner(ip, port):
    """ Attempts to grab a service banner from an open port """
    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            banner = sock.recv(1024).decode().strip()
            return banner if banner else "No banner detected"
    except (socket.timeout, ConnectionRefusedError):
        return "No banner detected"


def scan_target(target):
    """ Scans the target using Nmap for open ports & vulnerabilities """
    print(f"🚀 Scanning target: {target}")  # Debugging Log
    scanner = nmap.PortScanner()

    try:
        scanner.scan(target, arguments='-sV -Pn --script vuln')
        print(f"✅ Nmap scan completed for {target}")  # Debugging Log
    except Exception as e:
        print(f"❌ Nmap scan failed for {target}: {e}")
        return [{"error": f"Nmap scan failed: {e}"}]

    results = []

    if not scanner.all_hosts():
        print(f"⚠️ No active hosts detected for {target}")
        return [{"error": "No active hosts detected"}]

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto].keys():
                service = scanner[host][proto][port]['name']
                version = scanner[host][proto][port].get('version', 'Unknown')
                banner = get_banner(host, port)

                # Check for vulnerabilities
                cve_list = check_vulnerabilities(service, version)
                exploits = suggest_exploits(cve_list)

                results.append({
                    "host": host,
                    "port": port,
                    "service": service,
                    "version": version,
                    "banner": banner,
                    "vulnerabilities": cve_list,
                    "exploits": exploits
                })
                print(f"🟢 Found {service} ({version}) on port {port}")  # Debugging Log

    return results


def check_vulnerabilities(service, version):
    """ Searches for CVEs related to the detected service """
    query = f"{service} {version}" if version != "Unknown" else service
    print(f"🔍 Checking CVEs for {query}")  # Debugging Log

    try:
        response = requests.get(VULNERS_API_URL, params={'software': query}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cve_list = [cve['id'] for cve in data['data'].get('search', [])]
            return cve_list if cve_list else ["No known CVEs found"]
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Error fetching CVE data: {e}")
        return ["Error fetching CVE data"]

    return ["No known CVEs found"]


def suggest_exploits(cve_list):
    """ Suggests exploits from Exploit-DB for the given CVEs """
    return [{"CVE": cve, "exploit_url": f"{EXPLOIT_DB_URL}{cve}"} for cve in cve_list]


def run_exploit(target, exploit_type):
    """ Runs an exploit on the target based on the selected type """
    exploits = {
        "SMB Exploit (EternalBlue)": f"python eternalblue_exploit.py {target}",
        "SQL Injection Scanner": f"python sql_scanner.py {target}",
        "LFI Scanner": f"python lfi_scanner.py {target}",
        "Brute Force Attack": f"python brute_force.py {target}"
    }

    if exploit_type in exploits:
        command = exploits[exploit_type]
        print(f"🚀 Running exploit: {command}")  # Debugging Log
        try:
            os.system(command)
            return f"🚀 Exploit executed: {command}"
        except Exception as e:
            return f"❌ Exploit failed: {e}"
    else:
        return "❌ Invalid exploit type"


def penetration_test(targets):
    """ Runs penetration testing on multiple targets concurrently """
    print("🛠 Starting penetration testing...")
    final_report = {}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_results = {executor.submit(scan_target, target): target for target in targets}

        for future in concurrent.futures.as_completed(future_results):
            target = future_results[future]
            try:
                result = future.result()
                final_report[target] = result
                print(f"✅ Scan completed for {target}")
            except Exception as e:
                print(f"❌ Error scanning {target}: {e}")
                final_report[target] = [{"error": str(e)}]

    save_report(final_report)
    return final_report


def save_report(data):
    """ Saves the report in JSON & TXT formats """
    json_filename = "pentest_report.json"
    txt_filename = "pentest_report.txt"

    with open(json_filename, "w") as json_file:
        json.dump(data, json_file, indent=4)

    with open(txt_filename, "w") as txt_file:
        for target, results in data.items():
            txt_file.write(f"Target: {target}\n")
            for entry in results:
                if "error" in entry:
                    txt_file.write(f"  ❌ {entry['error']}\n")
                else:
                    txt_file.write(f"  - Port: {entry['port']}, Service: {entry['service']} ({entry['version']})\n")
                    txt_file.write(f"    Banner: {entry['banner']}\n")
                    txt_file.write(f"    Vulnerabilities: {', '.join(entry['vulnerabilities'])}\n")
                    txt_file.write(f"    Possible Exploits:\n")
                    for exploit in entry["exploits"]:
                        txt_file.write(f"      - {exploit['CVE']}: {exploit['exploit_url']}\n")
            txt_file.write("\n")

    print(f"📂 Report saved as {json_filename} and {txt_filename}")


if __name__ == "__main__":
    print(BANNER)
    targets = input("Enter target IPs (comma-separated): ").split(',')
    report = penetration_test(targets)
    print(json.dumps(report, indent=4))
