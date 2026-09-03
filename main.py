import logging
import os
import boto3
from dotenv import load_dotenv

from poller import get_findings
from enricher import build_technique_lookup, enrich_findings
from ticketer import create_ticket, load_processed, save_processed

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("main")

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
DETECTOR_ID = os.getenv("DETECTOR_ID")

MAX_FINDINGS_PER_RUN = 10


def run_pipeline():
    logger.info("=== GuardDutySync pipeline starting ===")

    session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION
    )

    # Stage 1: Poll
    findings = get_findings(session, DETECTOR_ID, max_results=MAX_FINDINGS_PER_RUN)
    total_alerts = len(findings)

    if total_alerts == 0:
        logger.info("No findings to process. Exiting.")
        return

    # Stage 2: Enrich
    lookup = build_technique_lookup()
    enriched = enrich_findings(findings, lookup)

    # Stage 3: Ticket
    processed_ids = load_processed()
    tickets_created = 0
    tickets_skipped = 0
    errors = 0

    for f in enriched:
        try:
            result = create_ticket(f, processed_ids)
            if result:
                tickets_created += 1
            else:
                tickets_skipped += 1
        except Exception as e:
            logger.error(f"Error creating ticket for finding {f.get('Id')}: {e}")
            errors += 1

    save_processed(processed_ids)

    logger.info("=== Pipeline run summary ===")
    logger.info(f"Total alerts fetched: {total_alerts}")
    logger.info(f"Tickets created: {tickets_created}")
    logger.info(f"Tickets skipped (duplicates): {tickets_skipped}")
    logger.info(f"Errors: {errors}")
    logger.info("=== GuardDutySync pipeline complete ===")


if __name__ == "__main__":
    run_pipeline()