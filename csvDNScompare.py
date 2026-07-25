import csv
import platform
import re
import subprocess
import telnetlib
from datetime import datetime
import tabulate

# Configuration
GNS3_HOST = "REDACTED"
GNS3_SERVER = f"REDACTED"
PROJECT_ID = "REDACTED"
CSV_PATH = "REDACTED"
ALLOWED_DNS = {"10.10.10.10", "10.10.10.20", "127.0.0.1", "127.0.0.53", "None Configured"} # Defining Approved DNS Servers/Configs

def execute_console_commands(
    host: str, port: int, username: str, password: str, commands: list
) -> str:
    """Logs into an Ubuntu console via Telnet and executes commands, returning output."""
    full_output = ""
    try:
        tn = telnetlib.Telnet(host, port, timeout=4)

        # Handle login prompts if required
        tn.write(b"\n")
        response = tn.read_until(b"login: ", timeout=2)
        if b"login:" in response:
            tn.write(username.encode("ascii") + b"\n")
            tn.read_until(b"Password: ", timeout=2)
            tn.write(password.encode("ascii") + b"\n")

        # Execute requested commands sequentially
        for cmd in commands:
            tn.write(cmd.encode("ascii") + b"\n")
            full_output += tn.read_until(b"$ ", timeout=3).decode(
                "utf-8", errors="ignore"
            )

        tn.close()
    except Exception:
        pass  # Return empty output if connection fails or times out

    return full_output


def get_device_info_via_console(
    host: str,
    port: int,
    username: str,
    password: str,
    check_ip: bool = False,
):
    # Retrieves IP (if DHCP) and configured DNS Server(s) via the device console.
    commands = [
        "cat /etc/resolv.conf",
        "resolvectl status 2>/dev/null || systemd-resolve --status 2>/dev/null",
    ]
    if check_ip:
        commands.insert(0, "hostname -I")

    console_output = execute_console_commands(
        host, port, username, password, commands
    )

 # 1. Parse IP Address (if requested)
    ip_address = None
    if check_ip:
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", console_output)
        if ip_match:
            ip_address = ip_match.group(0)

    # 2. Parse DNS Servers (matches nameserver or DNS Servers: entries)
    dns_servers = re.findall(
        r"(?:nameserver|DNS Servers:?)\s+((?:\d{1,3}\.){3}\d{1,3})",
        console_output,
    )

    # Clean and deduplicate found DNS IPs
    unique_dns = list(dict.fromkeys(dns_servers))
    dns_config = ", ".join(unique_dns) if unique_dns else "None Configured"

    return ip_address, dns_config

def ping_target_ip(target_ip: str) -> bool:
    # Sends an ICMP ping to the target IP address.
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_flag = "-w" if platform.system().lower() == "windows" else "-W"
    command = [
        "ping",
        param,
        "1",
        timeout_flag,
        "1000" if platform.system().lower() == "windows" else "1",
        target_ip,
    ]

    return (
        subprocess.call(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        == 0
    )





def main():
    table_device_status = []
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"Reading and processing devices from '{CSV_PATH}'...\n")

    with open(CSV_PATH, mode="r", newline="") as file:
        csv_reader = csv.reader(file)
        next(csv_reader)  # Skip header row

        for row in csv_reader:
            # Ensure row has basic minimum columns
            if len(row) < 4:
                continue

            device_id = row[0]
            device_name = row[1]
            raw_ip = row[2].strip()
            subnet = row[3]

            # Parse optional console & auth details from CSV
            console_port = (
                int(row[5]) if len(row) > 5 and row[5].isdigit() else None
            )
            username = row[7] if len(row) > 7 else ""
            password = row[8] if len(row) > 8 else ""

            target_ip = raw_ip
            needs_dhcp_ip = raw_ip.upper() == "DHCP"
            dns_config = "N/A"

            # Fetch console info if a console port is specified
            if console_port:
                print(
                    f"-> Querying console for {device_name} (Port {console_port})..."
                )
                discovered_ip, dns_config = get_device_info_via_console(
                    GNS3_HOST,
                    console_port,
                    username,
                    password,
                    check_ip=needs_dhcp_ip,
                )

                if needs_dhcp_ip:
                    if discovered_ip:
                        target_ip = discovered_ip
                    else:
                        target_ip = "DHCP-Unresolved"

            elif needs_dhcp_ip:
                target_ip = "DHCP-NoPort"

            # Check Ping Result
            if target_ip and not target_ip.startswith("DHCP-"):
                ping_success = ping_target_ip(target_ip)
                ping_res = "Success" if ping_success else "Failed"
                status = "Online" if ping_success else "Offline"
            else:
                ping_res = "Skipped"
                status = "Unknown"


            # Evaluate DNS Policy <> DNS Configurations Found
            # Added 7/26/2026
            # Parse the configured DNS servers and compare against ALLOWED_DNS

            if isinstance(dns_config, str):
                parsed_ips = [ip.strip() for ip in dns_config.split(",") if ip.strip()]
            elif isinstance(dns_config, list):
                parsed_ips = [str(ip).strip() for ip in dns_config]
            else:
                parsed_ips=[]

            unauthorized = [ip for ip in parsed_ips if ip not in ALLOWED_DNS]

            if not parsed_ips:
                dns_eval = "Error"
            elif unauthorized:
                dns_eval = "ALERT! Unathorized DNS Server(s)"
            else:
                dns_eval = "PASS"             




            table_device_status.append(
                [
                    current_time,
                    device_name,
                    raw_ip,
                    target_ip,
                    subnet,
                    status,
                    ping_res,
                    dns_config,
                    dns_eval
                ]
            )

    # Display Final Aggregated Results
    headers = [
        "TimeStamp",
        "Device Name",
        "CSV IP",
        "Resolved IP",
        "Subnet",
        "Status",
        "Ping Result",
        "Configured DNS",
        "DNS Evaluation"
    ]

    print(
        "\n" + tabulate.tabulate(table_device_status, headers=headers, tablefmt="grid")
    )
    

if __name__ == "__main__":
    main()
