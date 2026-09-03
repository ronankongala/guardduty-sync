import json
import os

import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

load_dotenv()

JIRA_DOMAIN = os.getenv("JIRA_DOMAIN")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")

url = f"https://{JIRA_DOMAIN}/rest/api/3/issue"

auth = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

payload = json.dumps({
    "fields": {
        "project": {"key": PROJECT_KEY},
        "summary": "GuardDutySync API Test",
        "issuetype": {"name": "Task"}
    }
})

response = requests.post(url, headers=headers, auth=auth, data=payload)

print("Status code:", response.status_code)
print("Response:", response.json())
