import csv
import tabulate
import napalm
from napalm import get_network_driver
from datetime import datetime


#Open the CSV and read contents
with open('resources/network_devices.csv', mode='r', newline='') as file:
    csv_reader = csv.reader(file)
    next(csv_reader) #Skips the header row & can be committed out if you want to include the header row in the output

#Create a table output that includes future functions which are Device Ping Status and DNS Configs
    tableDeviceStatus = []
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for row in csv_reader:
        if len(row) > 1:
            tableDeviceStatus.append([current_time, row[1], row[2], row[3], 'TBD', 'PingTBD', 'DNS_Unknown'])
    print(tabulate.tabulate(tableDeviceStatus, headers=['TimeStamp', 'Device Name','IP Address','Subnet', 'Status', 'Ping Results', 'DNS Status'], tablefmt="grid"))
