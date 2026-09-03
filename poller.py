import boto3
import logging
import os
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("poller")

def get_findings(session, detector_id, max_results=25):
    client = session.client("guardduty")

    # Get finding IDs
    list_response = client.list_findings(
        DetectorId=detector_id,
        MaxResults=max_results
    )
    finding_ids = list_response.get("FindingIds", [])

    if not finding_ids:
        logger.info("No findings returned from GuardDuty.")
        return []

    # Get full finding details
    details_response = client.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )
    findings = details_response.get("Findings", [])

    for f in findings:
        logger.info(
            f"Fetched finding | ID: {f.get('Id')} | Title: {f.get('Title')} | Severity: {f.get('Severity')}"
        )

    return findings


if __name__ == "__main__":
    session = boto3.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )

    DETECTOR_ID = os.getenv("DETECTOR_ID")
    findings = get_findings(session, DETECTOR_ID)
    logger.info(f"Total findings fetched: {len(findings)}")