import paramiko
import socket
import sys

# Target Device Details 
HOST = "REDACTED"
COMMON_PORTS = [22, 2222, 2200]  # Candidate SSH ports to check because 22 was timing out even though tcping confirmed it's open
USERNAME = "REDACTED"
PASSWORD = "REDACTED"

OLD_DNS = "203.0.113.10"
NEW_PRIMARY_DNS = "10.10.10.10"
NEW_SECONDARY_DNS = "10.10.10.20"


def find_open_port(host, ports):
    #Checks which TCP port is open and accepting socket connections.
    print(f"Checking for active SSH port on {host}...")
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            print(f"-> Found active port: TCP {port}")
            return port
    return None


# 1. Port Check
target_port = find_open_port(HOST, COMMON_PORTS)

if not target_port:
    print(f"\n[ERROR] Could not connect to {HOST} on ports {COMMON_PORTS}.")
    print("Please verify on 'pc2' that the SSH service is running and allowed through the firewall:")
    print("  Linux: 'sudo systemctl start ssh' && 'sudo ufw allow 22/tcp'")
    sys.exit(1)

# 2. SSH Client Setup & Execution
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    print(f"\nConnecting to pc2 ({HOST}:{target_port}) via SSH...")
    client.connect(
        hostname=HOST,
        port=target_port,
        username=USERNAME,
        password=PASSWORD,
        timeout=10
    )
    print("SSH connection established successfully!")

    # Update script: Swaps old DNS if present, or appends new DNS
    update_cmd = f"""
    if grep -q "{OLD_DNS}" /etc/resolv.conf; then
        sudo sed -i 's/{OLD_DNS}/{NEW_PRIMARY_DNS}/g' /etc/resolv.conf
    else
        echo "nameserver {NEW_PRIMARY_DNS}" | sudo tee -a /etc/resolv.conf > /dev/null
        echo "nameserver {NEW_SECONDARY_DNS}" | sudo tee -a /etc/resolv.conf > /dev/null
    fi
    """

    print("\nUpdating DNS configuration in /etc/resolv.conf...")
    stdin, stdout, stderr = client.exec_command(update_cmd)
    
    err = stderr.read().decode().strip()
    if err:
        print(f"Note/Warning during execution: {err}")
    else:
        print("DNS update command executed.")

    # 3. Verification Step
    print("\n--- Verified /etc/resolv.conf Output ---")
    stdin, stdout, stderr = client.exec_command("cat /etc/resolv.conf")
    print(stdout.read().decode().strip())
    print("---------------------------------------")

except paramiko.AuthenticationException:
    print("\n[AUTH ERROR] Failed to authenticate. Please check your username/password.")
except paramiko.SSHException as ssh_err:
    print(f"\n[SSH ERROR] Protocol error: {ssh_err}")
except Exception as e:
    print(f"\n[CONNECTION ERROR] {e}")

finally:
    client.close()
    print("\nSSH session closed.")
