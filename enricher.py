import json as _json
import logging
import os

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("enricher")

# GuardDuty finding type -> MITRE ATT&CK technique ID
FINDING_TYPE_TO_MITRE = {
    "Trojan:Runtime/DropPoint": "T1074",
    "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory": "T1611",
    "DefenseImpairment:RDS/ModifyAuthenticationProcess": "T1556",
    "Impact:IAMUser/CostHarvesting": "T1496",
    "Execution:Kubernetes/ExecInKubeSystemPod": "T1609",
    "Persistence:Kubernetes/MaliciousIPCaller.Custom": "T1078",
    "Impact:EC2/AbusedDomainRequest.Reputation": "T1071.001",
    "Persistence:Runtime/SuspiciousCommand": "T1059",
    "Impact:Kubernetes/TorIPCaller": "T1090.003",
    "DefenseEvasion:EC2/UnusualDNSResolver": "T1071.004",
    "Policy:Kubernetes/KubeflowDashboardExposed": "T1190",
    "Impact:Kubernetes/SuccessfulAnonymousAccess": "T1078.004",
    "Backdoor:Runtime/C&CActivity.B!DNS": "T1071.004",
}


def build_technique_lookup():
    with open("enterprise-attack.json", "r", encoding="utf-8") as f:
        bundle = _json.load(f)

    lookup = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_refs = obj.get("external_references", [])
        technique_id = next(
            (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
            None
        )
        if not technique_id:
            continue
        kill_chain = obj.get("kill_chain_phases", [])
        tactic = kill_chain[0].get("phase_name") if kill_chain else "Unknown"
        lookup[technique_id] = {
            "tactic": tactic,
            "name": obj.get("name"),
            "description": (obj.get("description") or "")[:300]
        }
    return lookup


def enrich_findings(findings, technique_lookup):
    enriched = []
    for f in findings:
        finding_type = f.get("Type", "")
        technique_id = FINDING_TYPE_TO_MITRE.get(finding_type)

        if not technique_id or technique_id not in technique_lookup:
            logger.info(f"No MITRE mapping for finding type: {finding_type}")
            f["attack_tactic"] = "Unmapped"
            f["attack_technique_name"] = "Unmapped"
            f["attack_technique_description"] = ""
        else:
            info = technique_lookup[technique_id]
            f["attack_tactic"] = info["tactic"]
            f["attack_technique_name"] = info["name"]
            f["attack_technique_description"] = info["description"]
            logger.info(
                f"Enriched | Type: {finding_type} | Technique: {technique_id} ({info['name']}) | Tactic: {info['tactic']}"
            )

        enriched.append(f)
    return enriched


if __name__ == "__main__":
    from poller import get_findings
    import boto3

    session = boto3.Session(
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )
    DETECTOR_ID = os.getenv("DETECTOR_ID")

    findings = get_findings(session, DETECTOR_ID)
    lookup = build_technique_lookup()
    enriched = enrich_findings(findings, lookup)
    logger.info(f"Total enriched findings: {len(enriched)}")