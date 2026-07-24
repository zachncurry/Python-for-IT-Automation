import csv
import re
import socket
import telnetlib
import requests
import tabulate

# GNS3 Server Details
GNS3_SERVER = "REDACTED"
PROJECT_ID = "REDACTED"
GNS3_HOST = "localhost"

# Hard coded this to test the Ping function and not the csv loop function
device_row = [
    "1001",
    "API",
    "10.10.10.200",
    "255.255.255.0",
    "Services",
    "8011",
    "Ubuntu",
    "ubuntu",
    "ubuntu",
]


def get_ip_from_console(
    host: str, port: int, username: str, password: str
) -> str:
    # Connects to the Ubuntu device console via Telnet to read its dynamic DHCP IP.
    try:
        tn = telnetlib.Telnet(host, port, timeout=5)

        # Handle login if prompted
        tn.write(b"\n")
        response = tn.read_until(b"login: ", timeout=3)
        if b"login:" in response:
            tn.write(username.encode("ascii") + b"\n")
            tn.read_until(b"Password: ", timeout=3)
            tn.write(password.encode("ascii") + b"\n")

        # Run command to fetch IP address
        tn.write(b"hostname -I\n")
        output = tn.read_until(b"\n", timeout=3).decode("utf-8")
        tn.close()

        # Extract IPv4 address using regex
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output)
        if ip_match:
            return ip_match.group(0)
    except Exception as e:
        print(f"[!] Could not query console on port {port}: {e}")

    return None


def ping_target_ip(target_ip: str) -> bool:
    """Sends a ICMP ping to the target IP address."""
    import subprocess
    import platform

    # Flag depending on OS (-n for Windows, -c for Linux/macOS)
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", target_ip]

    return subprocess.call(command, stdout=subprocess.DEVNULL) == 0


def main():
    dev_id, name, ip_field, mask, site, port, os_type, user, pwd = device_row

    print(f"Processing device: {name} ({os_type})...")

    # Resolve IP if specified as DHCP
    target_ip = ip_field
    if ip_field.upper() == "DHCP":
        print(f"-> IP set to DHCP. Polling console on port {port}...")
        discovered_ip = get_ip_from_console(GNS3_HOST, int(port), user, pwd)

        if discovered_ip:
            target_ip = discovered_ip
            print(f"-> Successfully acquired DHCP IP: {target_ip}")
        else:
            print("-> Unable to retrieve IP from DHCP.")
            target_ip = "Unassigned/Unknown"

    # Ping execution
    if target_ip not in ["DHCP", "Unassigned/Unknown"]:
        ping_success = ping_target_ip(target_ip)
        ping_result = "Success (Reply received)" if ping_success else "Failed"
        status = "Online" if ping_success else "Offline"
    else:
        ping_result = "Skipped (No IP)"
        status = "Unknown"

    # Display Results
    output_table = [
        [name, ip_field, target_ip, mask, site, port, status, ping_result]
    ]
    headers = [
        "Device",
        "CSV IP",
        "Resolved IP",
        "Subnet",
        "Site",
        "Port",
        "Status",
        "Ping Result",
    ]

    print("\n" + tabulate.tabulate(output_table, headers=headers, tablefmt="grid"))


if __name__ == "__main__":
    main()
