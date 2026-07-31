import csv
import platform
import re
import subprocess
import telnetlib
from datetime import datetime
import tabulate
from email.message import EmailMessage
import smtplib
import pandas as pd
import requests
import paramiko

    
# MARK: GNS3 Configuration
GNS3_HOST = "REDACTED"
GNS3_SERVER = f"REDACTED"
PROJECT_ID = "REDACTED"
#CSV File with Device Info
CSV_PATH = "REDACTED"
#DNS Server Configurations Allowed including Loopbacks and None Configured
ALLOWED_DNS = {"10.10.10.10", "10.10.10.20", "127.0.0.1", "127.0.0.53", "None Configured"} # Defining Approved DNS Servers/Configs
#Email Server Information
EMAIL_HOST = "REDACTED"
EMAIL_PORT = REDACTED
#Help Desk API Information
HELP_URL = "REDACTED"
HELP_BEARER_TOKEN = "REDACTED"
#Approved Named DNS Servers
SERVER_NODES = ["DNS1", "DNS2"]
#DNS Servers for Remediation & Per Allowed DNS Policy:
PRIMARY_DNS = "10.10.10.10"
SECONDARY_DNS = "10.10.10.20"
#Manages Session for DNS Analysis
session = requests.Session()


#MARK: DNS Analysis
def dns_analysis(Incident_Response, remediation_table):

    table_device_status = []
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\nℹ️ Reading and Processing Network Devices\n")

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
        "Time Stamp",
        "Device Name",
        "CSV IP",
        "Resolved IP",
        "Subnet",
        "Status",
        "Ping Result",
        "Configured DNS",
        "DNS Evaluation"
    ]

    #print("\n" + tabulate.tabulate(table_device_status, headers=headers, tablefmt="grid"))

    routing_logic(table_device_status, Incident_Response, remediation_table)



####################
####################
####################
####################
####################
####################
####################
####################
####################


#MARK: Routing Logic
def routing_logic(table_device_status, Incident_Response, remediation_table):
  #Added 7/27/2026
    #Reads table device status and determines either Log Success or Start Remediation
    #REFERENCE: https://docs.python.org/3/tutorial/datastructures.html
    #Updated 7/28/26 To manage Incident Response
    if any('ALERT! Unathorized DNS Server(s)' in row for row in table_device_status):
        print("\n🔴 Alert - DNS Compromised")
        Incident_Response = 1 + Incident_Response
        remediation_process(table_device_status, Incident_Response, remediation_table)
    else:
        if Incident_Response > 0:
            for row in remediation_table:
                if row[6] == "closed":
                    print(f"\n✅ DNS Remediation Completed Successfully for {row[1]}")
                elif row[6] == "N/A":
                    #remediation_process(table_device_status, Incident_Response, remediation_table)
                    print(f"\n✅ DNS Remediation Completed With Help Desk Ticket Errors for {row[1]}")
                else:
                    Incident_Response = 1 + Incident_Response
                    print("✅ Rogue DNS Configurations Resolved Successfully - ℹ️ Initiating Validation Process\n")
                    remediation_process(table_device_status, Incident_Response, remediation_table)
                    
                
        else:
            print("\n✅ DNS Validated Successfuly\n")



####################
####################
####################
####################
####################
####################
####################
####################
####################


#MARK: Ping Target IP
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


####################
####################
####################
####################
####################
####################
####################
####################
####################


#MARK: Get Device Info from Console
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


####################
####################
####################
####################
####################
####################
####################
####################
####################
    


#MARK: Execute Console Commands
def execute_console_commands(
    host: str, port: int, username: str, password: str, commands: list
) -> str:
    #Logs into an Ubuntu console via Telnet and executes commands, returning output.
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



####################
####################
####################
####################
####################
####################
####################
####################
####################


#MARK: Main Remediation Logic
def remediation_process(table_device_status, Incident_Response, remediation_table):


    existing_devices = {(existing_row[1]) for existing_row in remediation_table}

    for status_row in table_device_status:
        device_name = status_row[1]
        device_config = status_row[7]
        device_status = status_row[8]
        

        if device_status == "ALERT! Unathorized DNS Server(s)":
            if device_name not in existing_devices:
                #Timestamp, Device Name, Resolved IP, Subnet, Configured DNS
                rem_list = [status_row[0], status_row[1], status_row[3], status_row[4], status_row[7]]
                ticket_data = create_ticket(rem_list)
                if ticket_data:
                    combined_row = rem_list + ticket_data
                    remediation_table.append(combined_row)
                else:
                    remediation_table.append(rem_list)

                existing_devices.add(device_name)

        elif device_status == "PASS":
            if device_name in existing_devices:
                for rem_row in remediation_table:
                    if rem_row[1] == device_name and len(rem_row) > 5:
                        rem_row[4] = device_config
                        ticket_id = rem_row[5]
                        update_payload = [rem_row[1], rem_row[2], ticket_id, rem_row[6]]
                        ticket_status = update_ticket(update_payload)
                        if ticket_status:
                            rem_row[6] = ticket_status[0] if isinstance(ticket_status, list) else ticket_status
            
             
    #headers = [
    #        "Time Stamp",
    #        "Device Name",
    #        "Resolved IP",
    #        "Subnet",
    #        "Configured DNS",
    #        "Help Desk Ticket ID",
    #        "Ticket Status"
    #    ]


     
    #print("\n" + tabulate.tabulate(remediation_table, headers=headers, tablefmt="grid"))


    if any("open" in row or "Failed to Dynamically Create Ticket" in row for row in remediation_table):
            
            if Incident_Response == 1:
                print("\n⚠️ Attempting DNS Remediation Process")
                print("\n⚠️ Sending ALERT Email Notification")
                send_Alert(remediation_table)
                print("\n⚠️ Restarting DNS Servers")
                dns_Restart()
                print("\n⚠️ Connecting & Correcting Affected Devices")
                connect_Correct(remediation_table)
                print("\n⚠️ Initiating Re-evaluation of DNS Configurations on All Devices")
                dns_analysis(Incident_Response, remediation_table)
            elif Incident_Response > 3:
                print("\n🔴 Escalating to IT Security Team - Incident Response Level 3")
                #HOLDING SPACE FOR TICKET PRIORITY ESCALATION & UPDATED DESCRIPTION FUNCTION
                #HOLDING SPACE FOR ESCALATION EMAIL FUNCTION 
            else:
                print(f"\n⚠️ DNS Server Issue Not Resolved... Restarting Remediation... \n\033[1mℹ️ Attempt:{Incident_Response}\033[0m\n")
                print("\n⚠️ Connecting & Correcting Affected Devices")
                connect_Correct(remediation_table)
                print("\n⚠️ Initiating Re-evaluation of DNS Configurations on All Devices")
                dns_analysis(Incident_Response, remediation_table) 
    

    else:
        send_Notification(remediation_table)
        routing_logic(table_device_status, Incident_Response, remediation_table)
        


####################
####################
####################
####################
####################
####################
####################
####################
####################



#MARK: Send Alert Email
def send_Alert(remediation_table):

    #Convert Pyhon Table to Panda Dataframe for easier html conversaion
    df = pd.DataFrame(
        remediation_table,
        columns=["Time Stamp", "Hostname", "IP Address", "Subnet", "DNS Violation", "Help Desk Ticket ID", "Help Desk Ticket Status"]
        )

    #Get HTML email template
    with open("resources/alert_email.html", "r", encoding = "utf-8") as file:
        html_content = file.read()

    #Convert Python Table to Panda Dataframe to HTML
    table_html = df.to_html(index=False, border = 1)
    final_html = html_content.replace("{{remediation_table}}", table_html)


    #Construct Email Alert Message
    msg = EmailMessage()
    
    msg['Subject'] = "URGENT: Device Compromise Detected—Immediate Attention Required [Do not reply this is an automated message]"
    msg['From'] = "REDACTED"
    msg['To'] = "REDACTED"

    msg.set_content("This is an automated email.")
    msg.add_alternative(final_html, subtype="html")

    #Send Email
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.send_message(msg)
            print("\n✅ Email ALERT Sent Successfully!")
    except Exception as e:
            print(f"\n🔴 Failed to send email: {e}")



####################
####################
####################
####################
####################
####################
####################
####################
####################


#MARK: Create Ticket
#Create Help Desk Ticket for each device in the remediation table
def create_ticket(rem_list):


    headers = {
    "Authorization": f"Bearer {HELP_BEARER_TOKEN}",
    "Accept": "application/json"
    }

    payload ={
    "assigned_to": "Unassigned",
    "description": f"Device {rem_list[1]} (IP:{rem_list[2]}) has rouge DNS configured: {rem_list[4]}.",
    "priority": "high",
    "requester_email": "system@sytem.com",
    "status": "open",
    "title": f"Rogue DNS Server Found on {rem_list[1]} | Remediation in Progress"
    }

    

    try:
        response = requests.post(HELP_URL, headers=headers, json=payload)

        #print(response.status_code)
        #print(response.json())
        response_json = response.json()
        ticket_id = response_json.get("id")
        ticket_status = response_json.get("status")
        print(f"✅ Created Help Desk Ticket for {rem_list[1]}!")
        return [ticket_id, ticket_status]
    except Exception as e:
        ticket_id = "N/A"
        ticket_status = "Failed to Dynamically Create Ticket"
        print(f"🔴 Failed to create help desk ticket for {rem_list[1]}: {e}")
        return [ticket_id, ticket_status]
        
         

####################
####################
####################
####################
####################
####################
####################
####################
####################


#MARK: Stop/Start DNS
#Restart DNS Servers [This code is mostly found in start_gns3_network.py]
def get_nodes():
    
    r = session.get(f"{GNS3_SERVER}/v2/projects/{PROJECT_ID}/nodes")
    r.raise_for_status()
    return r.json()

def find_node_by_name(nodes, name):
    for node in nodes:
        if node["name"] == name:
            return node
    raise ValueError(f"Node not found: {name}")

def stop_node(node_id, node_name):
    r = session.post(f"{GNS3_SERVER}/v2/projects/{PROJECT_ID}/nodes/{node_id}/stop")
    r.raise_for_status()
    print(f"Stopped: {node_name}")


def start_node(node_id, node_name):
    r = session.post(f"{GNS3_SERVER}/v2/projects/{PROJECT_ID}/nodes/{node_id}/start")
    r.raise_for_status()
    print(f"Started: {node_name}")

def print_green(msg):
    print(f"\033[92m{'\n' + msg}\033[0m")

def print_red(msg):
    print(f"\033[31m{'\n' + msg}\033[0m")

def find_node_by_name(nodes, name):
    for node in nodes:
        if node["name"] == name:
            return node
    raise ValueError(f"Node not found: {name}")



def dns_Restart():
    nodes = get_nodes()

    print_red("Stopping server nodes...")
    for name in SERVER_NODES:
        node = find_node_by_name(nodes, name)
        stop_node(node["node_id"], node["name"])


    print_green("Restarting server nodes...")
    for name in SERVER_NODES:
        node = find_node_by_name(nodes, name)
        start_node(node["node_id"], node["name"])

#Restart DNS Servers^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

####################
####################
####################
####################
####################
####################
####################
####################
####################



#MARK: Connect & Correct
#Connect & Correct each affected device
def connect_Correct(remediation_table):

    
    #1. Read csv with credentials
    credentials_df = pd.read_csv("resources/network_devices.csv")

    #2. Read remediation_table
    for device in remediation_table:
        if device[6] == "open" or device[6] == "Failed to Dynamically Create Ticket":
            device_name = device[1]
            ip_address = device[2]
            old_dns = device[4]

            match = credentials_df[credentials_df["Device Name"] == device_name]

            if match.empty:
                print(f"Skipping {device_name} ({ip_address}): Credentials not found in CSV.")
                continue

            username = match.iloc[0]["Username"]
            password = match.iloc[0]["Password"]    

            #Pass CMD Line updates
            cmd = (
                f"grep -q '{old_dns}' /etc/resolv.conf && sudo sed -i 's/{old_dns}/{PRIMARY_DNS}/g' /etc/resolv.conf"
                f"|| (grep -q '{PRIMARY_DNS}' /etc/resolv.conf || echo 'nameserver {PRIMARY_DNS}' | sudo tee -a /etc/resolv.conf); "
                f"grep -q '{SECONDARY_DNS}' /etc/resolv.conf || echo 'nameserver {SECONDARY_DNS}' | sudo tee -a /etc/resolv.conf"
            )

            print(f"\nℹ️ Connecting to {device_name} ({ip_address}) — updating DNS to {PRIMARY_DNS} & {SECONDARY_DNS}...")

            try:
                with paramiko.SSHClient() as client:
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip_address, port=22, username=username, password=password, timeout=100)

                    # Run update command
                    client.exec_command(cmd)

                    # Verify result
                    _, stdout, _ = client.exec_command("cat /etc/resolv.conf")
                    print(f"ℹ️ Attempting to Update the /etc/resolv.conf File on {device_name}")
                    print(f"ℹ️ After Attempt File Reads: {stdout.read().decode().strip()}")
                    
                    
                    
            except Exception as e:
                print(f"🔴 Could not connect to {device_name} ({ip_address}): {e}")



####################
####################
####################
####################
####################
####################
####################
####################
####################


#MARK: Update Ticket
def update_ticket(rem_list):

  
           

        headers = {
        "Authorization": f"Bearer {HELP_BEARER_TOKEN}",
        "Accept": "application/json"
        }

        payload ={
        "description": f"Rouge DNS configuration on Device {rem_list[0]} (IP:{rem_list[1]}) has been resolved.",
        "status": "closed"
        }


        update_HELP_URL = f"{HELP_URL}/{rem_list[2]}"

        try:
            response = requests.patch(update_HELP_URL, headers=headers, json=payload)

            #print(response.status_code)
            #print(response.json())
            response_json = response.json()
            ticket_status = response_json.get("status")
            print(f"✅ Closed Help Desk Ticket for {rem_list[0]}!")
            return [ticket_status]
        except Exception as e:
            print(f"🔴 Failed to update help desk ticket for {rem_list[0]}: {e}")
            
                
        

####################
####################
####################
####################
####################
####################
####################
####################
####################



#MARK: Send Notification Email
def send_Notification(remediation_table):

    #Convert Pyhon Table to Panda Dataframe for easier html conversaion
    df = pd.DataFrame(
        remediation_table,
        columns=["Time Stamp", "Hostname", "IP Address", "Subnet", "Corrected DNS", "Help Desk Ticket ID", "Help Desk Ticket Status"]
        )

    #Get HTML email template
    with open("resources/notification_email.html", "r", encoding = "utf-8") as file:
        html_content = file.read()

    #Convert Python Table to Panda Dataframe to HTML
    table_html = df.to_html(index=False, border = 1)
    final_html = html_content.replace("{{remediation_table}}", table_html)


    #Construct Email Alert Message
    msg = EmailMessage()
    
    msg['Subject'] = "RESOLVED: DNS Service Issue and Device Compromise - All Issues Remediated [Do not reply this is an automated message]"
    msg['From'] = "REDACTED"
    msg['To'] = "REDACTED"

    msg.set_content("This is an automated email.")
    msg.add_alternative(final_html, subtype="html")

    #Send Email
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.send_message(msg)
            print("\n✅ Email ALERT Sent Successfully!")
    except Exception as e:
            print(f"\n🔴 Failed to send email: {e}")




####################
####################
####################
####################
####################
####################
####################
####################
####################




#MARK: Main
def main():
    Incident_Response = 0
    remediation_table = []
    dns_analysis(Incident_Response, remediation_table)



if __name__ == "__main__":
    main()
