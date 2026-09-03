import requests
from requests.auth import HTTPBasicAuth
import json
import logging
import os
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("ticketer")

JIRA_DOMAIN = os.getenv("JIRA_DOMAIN")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")

JIRA_URL = f"https://{JIRA_DOMAIN}/rest/api/3/issue"
AUTH = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

STATE_FILE = "processed_findings.json"


def load_processed():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    return set()


def save_processed(processed_ids):
    with open(STATE_FILE, "w") as f:
        json.dump(list(processed_ids), f)


def severity_to_priority(severity):
    if severity >= 7.0:
        return "High"
    elif severity >= 4.0:
        return "Medium"
    else:
        return "Low"


def create_ticket(enriched_finding, processed_ids):
    finding_id = enriched_finding.get("Id")
    title = enriched_finding.get("Title", "Untitled GuardDuty Finding")
    severity = enriched_finding.get("Severity", 0)
    priority = severity_to_priority(severity)

    if finding_id in processed_ids:
        logger.info(f"Skipping duplicate ticket for finding ID: {finding_id}")
        return None

    description_text = (
        f"Finding Type: {enriched_finding.get('Type')}\n"
        f"Severity: {severity}\n"
        f"Region: {enriched_finding.get('Region')}\n"
        f"Resource: {json.dumps(enriched_finding.get('Resource', {}), default=str)[:300]}\n"
        f"MITRE Tactic: {enriched_finding.get('attack_tactic')}\n"
        f"MITRE Technique: {enriched_finding.get('attack_technique_name')}\n"
        f"Technique Description: {enriched_finding.get('attack_technique_description')}\n"
        f"GuardDuty Finding ID: {finding_id}\n"
        f"Console Link: https://us-east-1.console.aws.amazon.com/guardduty/home?region=us-east-1#/findings"
    )

    payload = json.dumps({
        "fields": {
            "project": {"key": PROJECT_KEY},
            "summary": f"[GuardDuty] {title} ({finding_id})",
            "issuetype": {"name": "Task"},
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": description_text}]
                    }
                ]
            }
        }
    })

    response = requests.post(JIRA_URL, headers=HEADERS, auth=AUTH, data=payload)

    if response.status_code == 201:
        issue_key = response.json().get("key")
        logger.info(f"Created ticket {issue_key} for finding {finding_id} (Priority: {priority})")
        processed_ids.add(finding_id)
        return issue_key
    else:
        logger.error(f"Failed to create ticket: {response.status_code} {response.text}")
        return None