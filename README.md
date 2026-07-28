# Rogue DNS Server Detection & Remediation </br>Python for IT Automation




**Introduction**</br>
Act as a company's network administrator during a cybersecurity incident in which the internal Domain Name System (DNS) service is down and devices are resolving through a rogue DNS address. Your mission is to quickly identify the root cause, verify and correct configurations on impacted devices, and implement enduring safeguards to prevent recurrence. You will manage a GitLab-based project with working branches, develop Python scripts to enumerate devices, verify connectivity and DNS settings, automatically notify stakeholders, create remediation tickets, and restore the DNS service while ensuring all affected devices are properly reconfigured.</br>
_Note: I am actively committing code to a Gitlab repository from VS for the lab. However, I am using my GitHub as my single source of truth, backup, and portfolio repository._</br>

**Key Outcomes**</br>
- Integrate Python scripts, modules, packages, and libraries to automate networking tasks and processes.

**Network Diagram**</br>
_GSN3 Instance_</br>
<img width="687" height="730" alt="image" src="https://github.com/user-attachments/assets/2284ac39-f290-430c-8a01-8a95079f5250" />



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
_While specialty software exists, a simple PowerPoint organizational chart is helpful for mapping out your development process. Use it to build a visual hierarchy: outline each action, break down the steps to accomplish it, and identify the required data points. Doing this before writing any pseudocode helps you visualize the order of operations, plan third-party integrations, leverage existing APIs, and spot missing data. Though typically associated with Waterfall, this visual mapping is just as valuable for scoping Agile features while reducing complexity, aligning cross-functional teams, and streamlining stakeholder sign-off._
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
- EmailMessage 
- smtplib 
- pandas


**Code Development Progress/ Change Log**
1) [unitReadCSV.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/unitReadCSV.py): Confirms the ability to add a CSV file to the file structure within a folder, read, and process the contained data
2) [unitPing.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/unitPing.py): Confirms the ability to ping a device with hard coded host information
3) [csvPing.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/csvPing.py): Confirms the ability to read device information from a CSV file, ping each device, and return the results of each Ping to a table
4) [unitDNS.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/unitDNS.py): Confirms the ability to obtain a device DNS configuration settings with hard coded host information
5) [csvDNS.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/csvDNS.py): Confirms the ability to read device information from a CSV file, ping, and get DNS configuration details, adding the results of each to a table
6) [unitEmailAPI.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/unitEmailAPI.py): Confirms the ability to connect with the SMTP server and send hard coded email information
7) [csvDNScompare.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/csvDNScompare.py): Takes the csvDNS table and evaluates the current DNS configurations to our acceptable DNS configurations
8) [unitCompare.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/3bbbbc3f8e35f2829ded44b47bd396f0f9e21619/unitCompare.py): Adds a validation check if any devices have an alert to start the remediation process otherwise confirm success. This will be the decision tree point at the top of the loop will call the UnitEmailAPI, unitHelpDeskTicket, and retry functions to eventually trigger the final success email.
9) [csvDNSCompareEmail.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/32c48eb0134a75beb9fa69cf4ae08cc5e32758e4/csvDNSCompareEmail.py): This creates a subset of our initial table converting it into a panda table or data frame (because its easier to convert directly into an HTML table instead of doing another loop) and triggers the Alert Email. What is not shown is our resource folder which previously had the list of devices and now has the Alert Email template in HTML format.
10) [unitTicketAPI.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/457737ddb46200bb4b1b5f0e9fd719388aad40ca/unitTicketAPI.py): Testing the API call to Get and Push to the Help Desk Ticket via an API.
11) [csvDNS_Email_Ticket.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/dc9121f8a0e14555fa476241081e05453adac4d1/csvDNS_Email_Ticket.py): Added the creation of a ticket for each impacted machine.
12) [csvDNS_Email_Ticket_RestartDNS.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/a64058b92b62fdf07f1c7d68706077f098612a6a/csvDNS_email_ticket_RestartDNS.py): Added the help desk ticket information into the Remediation Table and Alert Email for additional context for end users and to manage the loop logic to determine when the incident is fully resolved. Then added the Stop and Start (Restarting) of the DNS Servers.
13) [unitConnectCorrect.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/449d535a6ea20c21b00f08fec9fa9bc033a59f3d/unitConnectCorrect.py): Hard coded information such as device information, username, password and rogue DNS IP to test connectivity, remove, and update. Found the 22 port while open but timing out requiring the need to add the ability to try other port numbers.

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

# Next Steps</br>

Take this fun, sudo code and turn it into a functional solution starting with the compare function.</br>

FOR each row in csvDNS.py{Summary Table}</br>
 Compare summary table in csvDNS.py{parse.DNSConfig} to DNS Policy</br>
  IF: </br>
   DNS Policy violated append.dnsViolationSummary</br>
   Call _Email Everybody Function_ (SMTP API)</br>
   Call _CYA Ticket System_ (Help Desk API)</br>
   Update Resume 🤣🤣</br>
  ELSE: </br>
   Print(DNS policy is giving compliance) _IYKYK_</br>


**Implementation Decision**</br>
**Decision Point:** What parts of the comparision and remediation efforts should I add into the current DNS query logic OR do I take the table output from the DNS file as input to a new table?</br>
**Decision Logic:** At first I thought I wanted to incorporate it to simplify the code however, after thinking through this (by writing this section) I now want to seperate them because we will need to recall this DNS query function to ensure our remeditaiton efforts were completed successfully. If we incorporate this downstream logic into the initial DNS query we would have had to add a counter and clear the counter instead of adding an ALERT or SUCCESS return to trigger downstream workflows and we will manage any loop conditions downstream in the remediation logic that ingest the return of ALERT or SUCCESS. In a production environment we may also want to consider an escalation if the remediation efforts failed X times such as additional email, escalated ticket priority, etc.

_This visual helps to outline the decision logic and how we will reuse the DNS query downstream_</br>
_A counter will be needed to track how many times the remediation efforts have failed and the logic can be if 0 and COMPLIANT do nothing else != 0 and COMPLIANT send Success Email_</br>
 <img width="565" height="628" alt="image" src="https://github.com/user-attachments/assets/daf9c23a-b5a8-440f-90d4-2a895413a253" />


## Remediation Step 1 </br>
[csvDNScompare.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/01613626c8dd8845d15437ce52f92bf895de892d/csvDNScompare.py)</br>
Here we take the full list of devices and evaluate our configured DNS servers to the DNS server policy/ acceptable DNS servers indicating an ALERT! in a new column to the right.</br>
<img width="1513" height="595" alt="image" src="https://github.com/user-attachments/assets/9863e60f-8bba-40c8-a644-7c10e81e8817" />

</br>

---

## Remediation Step 2 </br>
[csvDNSCompareEmail.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/32c48eb0134a75beb9fa69cf4ae08cc5e32758e4/csvDNSCompareEmail.py)</br>
Now that we have a table analyzing all devices and identified a malicious DNS is configured on several devices we create a new Remediation Table to manage those devices separately.</br>
<img width="442" height="146" alt="image" src="https://github.com/user-attachments/assets/0e3a7c68-d7c2-4eb8-a943-154c43c9f179" /></br>
Then we send the alert email notification to stakeholders informing them of the issue. </br>
_The table was converted to a panda dataframe then to HTML instead of creating another loop function._ </br></br>
<img width="933" height="420" alt="image" src="https://github.com/user-attachments/assets/3aded4ac-e71f-4b24-832b-4136565731c8" />
</br>

---

## Remediation Step 3 </br>
[csvDNS_Email_Ticket.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/dc9121f8a0e14555fa476241081e05453adac4d1/csvDNS_Email_Ticket.py)</br>
Use the loop to create the smaller remediation table and for each iteration in the loop Create a help desk ticket via Help Desk API and return the success message and ticket details back to the terminal.</br>
<img width="1388" height="274" alt="image" src="https://github.com/user-attachments/assets/93accd1c-b463-486c-a4b7-a230f79bf76d" />

---

## Remediation Step 4 </br>
[csvDNS_Email_Ticket_RestartDNS.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/a64058b92b62fdf07f1c7d68706077f098612a6a/csvDNS_email_ticket_RestartDNS.py)</br>
Here we connect to each DNS Server and restart their services.</br>
<img width="255" height="155" alt="image" src="https://github.com/user-attachments/assets/7134e186-97ab-4eaf-9271-53b87bee4448" /></br>
</br>
Also updated the email table to include the ticket id and status as well by parsing the JSON return from the Help Desk Ticket creation.</br>
This will provide state management as the data point to evaluate when we should send a resolution email.</br>
And in general having worked in IT organizations you want to ensure there is documentation outside of the inbox this provides stakeholders that reassurance for auditing purposes.</br>
<img width="1071" height="194" alt="image" src="https://github.com/user-attachments/assets/377f632f-1bdc-435e-962f-49a9cb7a8556" /></br>


<img width="1533" height="658" alt="image" src="https://github.com/user-attachments/assets/417879ff-71aa-4a05-97bb-588c759c9f95" /></br>


---


## Remediation Step 5 </br>
Connect and correct each noncompliant device on the network ensuring only policy approved DNS Servers are listed/configured</br>

To connect to each device we will need to pass Username and Password information which we did not include in our tables and only used once to Ping and retrieve DNS config in the very start.</br>
While there are several ways to do this I am going to write a CSV read to append our Remediation Table to briefly store this information within this function.</br>

**Sudo Code**</br>
- Read Remediation Table</br>
- Read CSV parsing only devices listed in the Remediation Table</br>
  - Append Username & Password</br> 
- Connect to each device using IP, Username, Password via SSH</br>
  - Remove rouge DNS IP (Just adding IPs is not enough as devices can store multiple)</br>
  - Add Primary DNS IP</br>
  - Add Secondary DNS IP</br>
- Retrieve DNS config</br>
  - Verify DNS config is now compliant</br> 
- Update Ticket Status</br>

[unitConnectCorrect.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/449d535a6ea20c21b00f08fec9fa9bc033a59f3d/unitConnectCorrect.py): Hard coded information such as device information, username, password and rogue DNS IP to test connectivity, remove, and update. Found the 22 port while open but timing out requiring the need to add the ability to try other port numbers. </br>



## Next Steps </br>
6) Send a Resolution Email to distribution list to include table summary</br>
7) Refactor the code: Currently I have too much logic in the Main() that could be moved to a function.
