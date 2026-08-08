# Rogue DNS Server Detection & Remediation </br>Python for IT Automation




**Introduction**</br>
During an active cybersecurity incident, the legitimate internal Domain Name System (DNS) service was disabled, causing corporate end-user devices and infrastructure to resolve traffic through an unauthorized rogue DNS address.</br>
The objective of this project is to identify the root cause of the hijack, verify and correct network client configurations, restore internal DNS service, and deploy permanent technical safeguards to prevent recurrence.</br></br>

**Key Objectives**</br>
- **Root Cause Analysis:** Isolate the malicious actor or rouge server and determine the vector used to alter client DNS settings (e.g., rogue DHCP server, local host modifications, or compromised router configs).</br>
- **Automated Audit & Verification:** Enumerate all network endpoints and continuously inspect DNS resolver settings and network connectivity.</br>
- **Incident Communication & Tracking:** Automatically alert critical stakeholders and generate remediation tickets for impacted hosts.</br>
- **Service Restoration & Hardening:** Bring legitimate internal DNS servers back online, revert rogue configurations, and enforce DNS security policy safeguards.</br>

**Network Diagram**</br>
_GSN3 Instance_</br>
<img width="687" height="730" alt="image" src="https://github.com/user-attachments/assets/2284ac39-f290-430c-8a01-8a95079f5250" />


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
14) [csvConnectCorrect.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/09488f6ab22c8a452652fbeff2ccf608db3db7e0/csvConnectCorrect.py): Incorporated the unit DNS Config script with several changes however a success!
15) [RemediationFinal.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/1d42c50dc0dbd6020eebfe74213bb8129d6a1e4f/RemediationFinal.py): Restructured the logic to address ongoing Rogues DNS Server attacks, added the final notification email, added the update Help Desk Ticket, and final remediation table/results. 

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

I went a head and refactored the code to minimize the Main() by adding a new function, added MARK notation for easier searching, and re-ordered the functions in a more logical order.</br>
Also added a state management integer to trigger an escalation after 3 attempts.</br>

[csvConnectCorrect.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/09488f6ab22c8a452652fbeff2ccf608db3db7e0/csvConnectCorrect.py)</br>


<img width="1086" height="244" alt="image" src="https://github.com/user-attachments/assets/da059688-503b-4f0e-9b37-ae9e7841a978" /></br>
<img width="1084" height="394" alt="image" src="https://github.com/user-attachments/assets/19d65f2e-b4a3-448d-a897-7884b191bc95" /></br>
<img width="1086" height="162" alt="image" src="https://github.com/user-attachments/assets/8f7bcaae-68cd-45de-994f-014e2ea26785" /></br>
<img width="400" height="250" alt="image" src="https://github.com/user-attachments/assets/3d5b9a63-6be5-449e-a739-9676c4d08b5b" /></br>
<img width="1086" height="519" alt="image" src="https://github.com/user-attachments/assets/9bd8af07-880c-4136-bafd-1e0129c74fb1" /></br>

Thankfully I had already started on logic and max try handling because now the lab is throwing errors and happy to report my script handles it just fine!</br>

I still need to update the status of the tickets. I added this to the scope so I can include the information into the final email for the first portion of this lab.


---

## Remediation Step 6 </br>
[RemediationFinal.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/1d42c50dc0dbd6020eebfe74213bb8129d6a1e4f/RemediationFinal.py)</br>
_Ohhh - Call me the barber because I got those edge cases!_ ✂️🤣🤣 

**Changes Made**</br>
- Restructured the logic to address an ongoing Rogues DNS Server attack (simulated by the lab)
- Added the final resolution email
- Added update Help Desk Ticket
- And determined final remediation results

**Resolved Email Notification**</br>
<img width="1506" height="571" alt="image" src="https://github.com/user-attachments/assets/1d97a330-694d-4fd9-9373-b2689282145d" /></br>
<img width="1518" height="139" alt="image" src="https://github.com/user-attachments/assets/0524a6e8-eebc-4107-9676-94949ed811b3" /></br>




 **Terminal Output**</br>
 _I removed the tables used for troubleshooting and added dynamic statements in the terminal for a better user experience so that anyone could understand the actions/status of this program._</br>
 _Re-ran the lab on 8/1/26 to get better terminal images and the lab ran a different pattern showing all 4 devices already compromised instead of the 3 then 1 pattern which is why having a good lab is so important to test your ideas!_
<img width="654" height="322" alt="image" src="https://github.com/user-attachments/assets/6e7c5294-273d-435d-b740-060cbffe23f1" /></br>
<img width="758" height="374" alt="image" src="https://github.com/user-attachments/assets/0f99daa2-535e-48b0-810f-e26585359781" /></br>
<img width="861" height="309" alt="image" src="https://github.com/user-attachments/assets/ac61f5c0-5ba3-4350-87f2-8151fabff4fc" /></br>
<img width="763" height="381" alt="image" src="https://github.com/user-attachments/assets/b2ee8169-b2ab-44ea-98a7-54a6028184d9" /></br>
<img width="801" height="261" alt="image" src="https://github.com/user-attachments/assets/27573eba-d72a-4e1e-bf59-a8a39c146f4a" /></br>




**All jokes aside... I enjoy learning not only by doing but through feedback and collaboration as well.**</br>
**If you have ideas on how this could be even better or where I could improve let's collaborate!**</br>
**Connect with me on LinkedIn:**</br>
https://www.linkedin.com/in/zachary-curry-pmp</br>
</br>
**More to Come for Part 2...**



## Milestone Reflection </br>
While there is more to do on this project I would like to take a moment and document lessons learned and share what I would have done differently.</br>
**Lessons Learned**</br>
- **Depth of Value:** How to connect to devices on the network through coding/automation. Before I was a wizard at the UI meaning I could click around until I found the IP & DNS configurations on a computer. Then I advanced my knowledge through obtaining hands on experience with Linux (Linux Essentials Certification) and networking devices (CCNA Certification). This takes that fundamental knowledge to the next level. For example, when I needed to resolve the IP assignments from the DHCP server, I knew what this meant and the process required to trigger, wait, and retrieve helping me to understand what to search for in libraries/ coding advice.
- **Threat Reality & Importance of Training:** How quickly a bad actor can change the entire network. Hint it is seconds. I knew network device was important but now I truly understand that once someone gains access to a network you have lost control. Before when I did required monthly phishing email training videos I thought it was annoying, now I think how can we get more people to understand just how important they are. I think a a value add for both technical and non-technical employees is to see the code work in real time or to escalate how we train for example sending a phishing email and if an employee clicks on it - lock their computer and require them to check in with a training team in person before unlocking their computer to demonstrate how real the threat actually is.
- **Planning:** I have always enjoyed planning as my mentor once told me plan with a map but follow the terrain. This was very real during this lab because the lab would modify its actions as I delivered more code, thankfully I had planned and already documented edge cases (not all) to consider which saved me a lot of time.
- **Patience & Pacing - Balance**: This is probably my most profound. The lab was a VM that only allowed six hours at a time, you could not hit extend, you could not pause, and once you stopped it all work was lost. You also could not copy and paste blocks larger than 20 lines at a time forcing me to connect my VS to Gitlab on the VM sometimes twice a day. Towards the end it took about 30 minutes to get reset. Additionally, once I ran my code to test in the lab I had a choice to either start over or manually reconfigure devices which did not match the behavior of the lab itself. Great learning experience both for the task at hand and personally. At first, I was annoyed... I was dissatisfied😉😉; however, I learned to be comfortable extending my timeline and ending the day even though I had more to accomplish working to be fresh the next day. Such a valuable life lesson to relearn throughout my life, a blessing really.
  - From this I also learned you can download multiple packages at a time, for example: "pip install pandas tabulate requests paramiko" downloads pandas, tabulate, requests, and paramiko in order from the single command.
  

**What I Would Have Done Differently**
 - **Planning:** Everything is 20/20 once you have done it... I missed a few edge cases and I now see the gap in my planning. I did not write out the combination of variable states that would be important making my final 48 hours focused on bug hunting. If I would have documented all combinations such as: Pass Initial Review - Ticket: Open, Failed Review - Ticket: Closed, I would have done better at finding ALL the edge cases to ensure it is bullet proof. My planning was focused mostly on workflow and I anticipated many of the states but missed the smaller edge cases causing the delay.
 - **Centralized Decision Function:** Currently the logic is spread across a few functions which is not ideal for anyone trying to advance this code base and potentially if I had done better planning I may have been able to unify the logic into a singular function.


## DNS Server Configurations</br>
Now we are moving upstream in the DNS validation by analyzing the DNS Server Configurations and then ensuring all devices are available by pinging each one.</br>
If they are not available we need to then analyze if our DNS Server Configs have changed to start remediation.</br>
<img width="678" height="702" alt="image" src="https://github.com/user-attachments/assets/6974a6e3-bdb0-4f83-adae-b17cb6715044" />



Abstract the DNS config records from each server creating a backup (example Google 8.8.8.8)</br>
Before coding anything I want to make sure I can access these from the Server Command Line and understand what exactly is expected.</br>
For _meow_ we will use the cat (short for concatenate) function to read the contents of /etc/bind/named.conf.local </br>
<img width="519" height="535" alt="image" src="https://github.com/user-attachments/assets/d1ac1635-3e53-40fe-9588-ead819d086c0" />

Then we use Netmiko a vendor neutral network automation library to help us connect and retrieve these results programmatically, copy, and add to our DNS Backup Files.</br>
[UnitDNS_dump.py](https://github.com/zachncurry/Rogue-DNS-Server-Detection-and-Remediation/blob/c2a47cc8bf673de843b5feccb2d0ab361f60e60b/unitDNS_dump.py) Unit testing the DNS Configuration dump. </br>
I did first try the file directly and received guidance to use "resolvectl status" instead. That is the thing with coding... The hardest part is getting started made easier by planning first and then adjusting based on the feedback/errors received.</br>_Just like life!_</br>

## Verify all devices are available by Pinging each one
We already built this functionality into our script so no new development is required.</br>
What we will do is now build a new workflow and a new table ping_remediation_table to manage the DNS Config errors.</br>
<img width="615" height="396" alt="image" src="https://github.com/user-attachments/assets/120119a4-bc71-4b93-be80-1b976d4d2a43" />

## Send Device Unavailable Email
The requirements are to include each device's information in the Email Subject Line whereas before we included a summary table and sent one email.</br>
Now we will send multiple emails, one for each device.




## Next Steps</br>
3) Verify the DNS configs for each DNS server and if altered incorrectly send an Alert Email
4) Add a log file to document system checks, modifications, errors
5) Add time.sleep function to automatically run every x period
