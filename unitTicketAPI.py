import requests

url = "REDACTED"
bearer_token = "REDACTED"

headers = {
"Authorization": f"Bearer {bearer_token}",
"Accept": "application/json"
}

#Get Help Desk Tickets
response = requests.get(url, headers=headers)

if response.status_code == 200:
    print("Success!")
    #print(response.json())
else:
    print(f"Failed with status code: {response.status_code}")
    #print(response.text)



payload ={
  "assigned_to": "Unassigned",
  "description": "TBD",
  "priority": "high",
  "requester_email": "system@system.com",
  "status": "open",
  "title": "Rogue DNS Server Found - Remediation in Progress"
}

response = requests.post(url, headers=headers, json=payload)

print(response.status_code)
print(response.json())
