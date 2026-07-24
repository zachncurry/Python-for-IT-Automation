import csv
import re
import socket
import telnetlib
import subprocess
import platform
import tabulate

# GNS3 Server Details
GNS3_SERVER = "REDACTED"
PROJECT_ID = "REDACTED"
GNS3_HOST = "localhost"

# Single device row data
device_row = [
    "REDACTED",
    "REDACTED",
    "REDACTED",
    "REDACTED",
    "REDACTED",
    "REDACTED",
    "REDACTED",
    "REDACTED",
    "REDACTED",
]


def execute_console_commands(host: str, port: int, username: str, password: str, commands: list) -> str:
    """Logs into the Ubuntu console via Telnet and executes a series of commands, returning full output."""
    full_output = ""
    try:
        tn = telnetlib.Telnet(host, port, timeout=5)

        # Handle login
        tn.write(b"\n")
        response = tn.read_until(b"login: ", timeout=2)
        if b"login:" in response:
            tn.write(username.encode("ascii") + b"\n")
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode("ascii") + b"\n")

        # Execute requested commands
        for cmd in commands:
            tn.write(cmd.encode("ascii") + b"\n")
            full_output += tn.read_until(b"$ ", timeout=3).decode("utf-8", errors="ignore")

        tn.close()
    except Exception as e:
        print(f"[!] Console connection error on port {port}: {e}")

    return full_output


def get_device_info_via_console(host: str, port: int, username: str, password: str, check_ip: bool = False):
    """Retrieves IP (if DHCP) and configured DNS Server(s) via the device console."""
    commands = [
        "cat /etc/resolv.conf",
        "resolvectl status 2>/dev/null || systemd-resolve --status 2>/dev/null"
    ]
    if check_ip:
        commands.insert(0, "hostname -I")

    console_output = execute_console_commands(host, port, username, password, commands)

    # 1. Parse IP (if requested)
    ip_address = None
    if check_ip:
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", console_output)
        if ip_match:
            ip_address = ip_match.group(0)

    # 2. Parse DNS Servers (Extract nameserver entries from /etc/resolv.conf or resolvectl)
    dns_servers = re.findall(r"(?:nameserver|DNS Servers:?)\s+((?:\d{1,3}\.){3}\d{1,3})", console_output)
    
    # Clean and deduplicate found DNS IPs
    unique_dns = list(dict.fromkeys(dns_servers))
    dns_config = ", ".join(unique_dns) if unique_dns else "None Configured"

    return ip_address, dns_config


def resolve_hostname(ip_address: str) -> str:
    """Performs reverse DNS lookup from local host to check PTR resolution."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        return host
    except (socket.herror, socket.gaierror, OverflowError):
        return "No PTR Record"


def ping_target_ip(target_ip: str) -> bool:
    """Sends an ICMP ping to the target IP address."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    command = ["ping", param, "1", timeout_flag, "1000" if platform.system().lower() == "windows" else "1", target_ip]

    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def main():
    dev_id, name, ip_field, mask, site, port, os_type, user, pwd = device_row

    print(f"Processing device: {name} ({os_type})...")

    target_ip = ip_field
    needs_dhcp_ip = (ip_field.upper() == "DHCP")

    # Get Console details (DHCP IP if needed + Configured DNS Servers)
    print(f"-> Querying console on port {port} for DNS Configuration...")
    discovered_ip, dns_servers = get_device_info_via_console(
        GNS3_HOST, int(port), user, pwd, check_ip=needs_dhcp_ip
    )

    if needs_dhcp_ip:
        if discovered_ip:
            target_ip = discovered_ip
            print(f"-> Successfully acquired DHCP IP: {target_ip}")
        else:
            print("-> Unable to retrieve IP from DHCP.")
            target_ip = "Unassigned/Unknown"

    # Reverse DNS Lookup check
    ptr_record = resolve_hostname(target_ip) if target_ip not in ["DHCP", "Unassigned/Unknown"] else "N/A"

    # Ping execution
    if target_ip not in ["DHCP", "Unassigned/Unknown"]:
        ping_success = ping_target_ip(target_ip)
        ping_result = "Success" if ping_success else "Failed"
        status = "Online" if ping_success else "Offline"
    else:
        ping_result = "Skipped"
        status = "Unknown"

    # Display Results
    output_table = [
        [name, ip_field, target_ip, mask, site, port, status, ping_result, dns_servers, ptr_record]
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
        "Configured DNS",
        "Reverse DNS (PTR)",
    ]

    print("\n" + tabulate.tabulate(output_table, headers=headers, tablefmt="grid"))


if __name__ == "__main__":
    main()
