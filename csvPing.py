import csv
import re
import socket
import telnetlib
import subprocess
import platform
from datetime import datetime
import tabulate

# Configuration
GNS3_HOST = "REDACTED"
GNS3_SERVER = f"REDACTED"
PROJECT_ID = "REDACTED"
CSV_PATH = "REDACTED"


def get_ip_from_console(host: str, port: int, username: str, password: str) -> str:
    # Connects to a node's console port via Telnet to retrieve its DHCP-assigned IP.
    try:
        tn = telnetlib.Telnet(host, port, timeout=3)
        tn.write(b"\n")
        
        # Read initial prompt to check if login is required
        response = tn.read_until(b"login: ", timeout=2)
        if b"login:" in response:
            tn.write(username.encode("ascii") + b"\n")
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode("ascii") + b"\n")

        # Query IP address (works for Linux/Ubuntu nodes)
        tn.write(b"hostname -I\n")
        output = tn.read_until(b"\n", timeout=3).decode("utf-8", errors="ignore")
        tn.close()

        # Extract IPv4 address using regex
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
        if ip_match:
            return ip_match.group(0)
    except Exception:
        pass  # Return None if console connection times out or fails

    return None


def ping_target_ip(ip_address: str) -> bool:
    # Sends a single ICMP ping to the specified IP address
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", "-w", "1000" if platform.system().lower() == "windows" else "1", ip_address]
    
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def main():
    table_device_status = []
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"Reading devices from '{CSV_PATH}'...\n")

    with open(CSV_PATH, mode="r", newline="") as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # Skip header row

        for row in csv_reader:
            # Ensure row has enough columns
            if len(row) < 4:
                continue

            device_id = row[0]
            device_name = row[1]
            raw_ip = row[2].strip()
            subnet = row[3]
            
            # Optional credentials/ports if present in CSV
            console_port = int(row[5]) if len(row) > 5 and row[5].isdigit() else None
            username = row[7] if len(row) > 7 else ""
            password = row[8] if len(row) > 8 else ""

            target_ip = raw_ip

            # Resolve DHCP if necessary
            if raw_ip.upper() == "DHCP":
                if console_port:
                    print(f"Polling console for {device_name} (Port {console_port})...")
                    discovered_ip = get_ip_from_console(GNS3_HOST, console_port, username, password)
                    target_ip = discovered_ip if discovered_ip else "DHCP-Unresolved"
                else:
                    target_ip = "DHCP-NoPort"

            # Perform Ping Check
            if target_ip and not target_ip.startswith("DHCP-"):
                success = ping_target_ip(target_ip)
                ping_res = "Success" if success else "Failed"
                status = "Online" if success else "Offline"
            else:
                ping_res = "Skipped"
                status = "Unknown"

            table_device_status.append([
                current_time,
                device_name,
                raw_ip,
                target_ip,
                subnet,
                status,
                ping_res
            ])

    # Display final table output
    headers = [
        "TimeStamp",
        "Device Name",
        "Configured IP",
        "Resolved IP",
        "Subnet",
        "Status",
        "Ping Results"
    ]
    print("\n" + tabulate.tabulate(table_device_status, headers=headers, tablefmt="grid"))


if __name__ == "__main__":
    main()
