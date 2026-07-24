# Rogue DNS Server Detection & Remediation </br>Python for IT Automation




**Introduction**</br>
Act as a company's network administrator during a cybersecurity incident in which the internal Domain Name System (DNS) service is down and devices are resolving through a rogue DNS address. Your mission is to quickly identify the root cause, verify and correct configurations on impacted devices, and implement enduring safeguards to prevent recurrence. You will manage a GitLab-based project with working branches, develop Python scripts to enumerate devices, verify connectivity and DNS settings, automatically notify stakeholders, create remediation tickets, and restore the DNS service while ensuring all affected devices are properly reconfigured.

**Key Outcomes**</br>
- Integrate Python scripts, modules, packages, and libraries to automate networking tasks and processes.

## Part One
**Scenario**</br>
As the network administrator for your company, you are alerted to a cybersecurity incident involving a DNS service outage. The internal DNS service is currently down, and you discover that several network devices have been reconfigured to use an unauthorized, potentially malicious DNS address. Immediate action is required to restore proper DNS functionality and secure the network.

 
**Problem Statement:**</br>
I am responsible for identifying the root cause of the DNS resolution issue and restoring normal operations. This includes investigating the source of the unauthorized DNS changes, verifying and correcting DNS configurations on all affected devices, and implementing immediate remediation steps to secure the network against further compromise.

## Part Two
**Scenario**</br>
After resolving the immediate DNS service outage and restoring correct DNS configurations on all network devices, you recognize the need to prevent similar incidents in the future. As the network administrator, you are responsible for implementing proactive measures to detect and respond to unauthorized DNS changes or service disruptions before they impact business operations.

**Problem Statement:** </br>
To ensure ongoing network security and reliability, you must design and implement a solution that regularly monitors DNS configurations and device status across the network. This solution should automatically alert stakeholders if any anomalies or unauthorized changes are detected, helping prevent future DNS-related attacks or outages.


# Process Overview

**Strategy:**
- Create a plan using established Project Management Book of Knowledge and Systems Engineering best practices
- Keep development/ test cycles small to reduce the complexity of errors

**Architecture Choices:**
- Leverage GitHub as my single source of truth for documentation.
- This lab provides a CSV with network devices. Approaching this as though the CSV was generated upstream for our use and not writing code to discover devices/nodes on the network.
- Create unit tests for each action such as Ping, Get DNS Config, etc then add a loop to try all devices in the CSV working to keep dev/test cycles as small as possible.


**Tactical Approach/ Systems Thinking/ Work Break Down Structure**
- Outline each required action
  - Read/ Import CSV
  - Ping Each Device
  - Query DNS Config Settings
  - Compare DNS Config to Expected DNS Config (DNS1 Server @ 10.10.10.10 or DNS2 Server @ 10.10.10.20)
  - Create Alert/ Trigger to Initiate Remediation
    - Create Work Ticket with API Call
    - Send Email Warning Notification
    - Restart DNS Servers
    - Update DNS Configs in Impacted Devices
    - Connect to each Impacted Device and Ensure Config Changes are accurate
    - Send Resolution Email 
- Identify what data is required for each step such as Device Name, IP Address, SubNet, Username, Password, etc
- Identify what to show in the Terminal and how either line by line or table summary
- Develop a unit test for each required action
- Expand the unit test to include all devices listed in the CSV
- Incorporate the multiple, modular functions into a singular, unified script to complete the end-to-end Initiation, Analysis, and Remediation process that could be setup to run on a chosen schedule automatically.

**Formal Work Break Down Structure (It's the PMP in Me!)</br>**
_While specialty software exists, a simple PowerPoint organizational chart is helpful for mapping out your development process. Use it to build a visual hierarchy: outline each action, break down the steps to accomplish it, and identify the required data points. Doing this before writing any pseudocode helps you visualize the order of operations, plan third-party integrations, leverage existing APIs, and spot missing data. Though typically associated with Waterfall, this visual mapping is just as valuable for scoping Agile features while reducing complexity, aligning cross-functional teams, and streamlining client sign-off._
<img width="1347" height="521" alt="image" src="https://github.com/user-attachments/assets/55f09be2-d6d1-4f5a-b500-9c38e6cd0e03" />
<img width="390" height="677" alt="image" src="https://github.com/user-attachments/assets/cdd249f6-2df0-4a27-a348-efe97a95d707" />

**Libraries Utilized:**
- CSV
- Tabulate
- Requests
- Platform
- re
- Subprocess
- Telnetlib
- Datetime


**Code Development Progress**
1) unitReadCSV.py
2) unitPing.py
3) csvPing.py
4) unitDNS.py
5) csvDNS.py

 </br></br>  

## Initial Results</br>
After initializing the network on GSN3, pinging the devices, and obtaining their DNS Configuration records issues have been found.</br>
Our network is configured to use two DNS Servers located at 10.10.10.10 and 10.10.10.20 however an invalid DNS Server of 203.0.113.10 has been discovered.</br> 
_127.0.0.53 is a loopback address common in networking_</br>
_203.0.113.10 is a research allocated IP4 address representing a malicious IP address_</br>
Here are the terminal results of the csvDNS.py file:
<img width="1245" height="322" alt="image" src="https://github.com/user-attachments/assets/9e5c51ee-26dc-402c-8626-fd991c0844be" />
<img width="1245" height="600" alt="image" src="https://github.com/user-attachments/assets/979f21a5-9b48-4859-ae8a-ad88f23ff785" />

**Required Remediation Steps**</br>
1) Analyze each device for any DNS noncompliance
2) Send an Alert Email to distribution list to include table summary
3) Create a Help Desk Ticket for each noncompliant device
4) Restart all DNS servers
5) Connect and correct each noncompliant device on the network ensuring only policy approved DNS Servers are listed/configured
6) Send a Resolution Email to distribution list to include table summary


