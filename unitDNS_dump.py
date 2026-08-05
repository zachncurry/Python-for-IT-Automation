from netmiko import ConnectHandler

# 1003,DNS1,10.10.10.10,255.255.255.0,Services ,5013,Ubuntu,ubuntu,ubuntu

dns1_server = {
    "device_type": "linux",
    "host": "10.10.10.10",
    "username": "ubuntu",    
    "password": "ubuntu",
}

net_connect = ConnectHandler(**dns1_server)
output = net_connect.send_command("resolvectl status")
print(output)
net_connect.disconnect()
