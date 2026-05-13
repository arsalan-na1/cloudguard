import logging
import os
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from remediation import get_remediation

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE_FINDINGS = os.environ.get("DYNAMODB_TABLE_FINDINGS", "cloudguard-findings")
TABLE_POSTURE = os.environ.get("DYNAMODB_TABLE_POSTURE", "cloudguard-posture-scores")

SEVERITY_DEDUCTIONS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 5, "LOW": 0}


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_account_id():
    return boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]


def _make_finding(rule_id, account_id, timestamp, service, severity, resource_arn, title, description, remediation="", region=None):
    return {
        "finding_id": f"{rule_id}-{account_id}-{timestamp}",
        "timestamp": timestamp,
        "account_id": account_id,
        "region": region or REGION,
        "service": service,
        "severity": severity,
        "resource_arn": resource_arn,
        "title": title,
        "description": description,
        "remediation": remediation,
        "status": "OPEN",
        "source": "auditor",
    }


# ---------------------------------------------------------------------------
# Audit rules
# ---------------------------------------------------------------------------

def _check_root_access_keys(account_summary, account_id, timestamp):
    if account_summary.get("AccountAccessKeysPresent", 0) > 0:
        finding = _make_finding(
            rule_id="iam-root-access-keys",
            account_id=account_id,
            timestamp=timestamp,
            service="iam",
            severity="CRITICAL",
            resource_arn=f"arn:aws:iam::{account_id}:root",
            title="Root account has active access keys",
            description=(
                "The AWS root account has programmatic access keys. Root keys bypass all "
                "IAM policies and cannot be scoped down to least privilege."
            ),
        )
        finding["remediation"] = get_remediation(finding)
        return finding
    return None


def _check_root_mfa(account_summary, account_id, timestamp):
    if account_summary.get("AccountMFAEnabled", 1) == 0:
        finding = _make_finding(
            rule_id="iam-root-mfa-disabled",
            account_id=account_id,
            timestamp=timestamp,
            service="iam",
            severity="CRITICAL",
            resource_arn=f"arn:aws:iam::{account_id}:root",
            title="Root account MFA is not enabled",
            description=(
                "The root account does not have multi-factor authentication enabled, "
                "making it vulnerable to credential theft and account takeover."
            ),
        )
        finding["remediation"] = get_remediation(finding)
        return finding
    return None


def _check_cloudtrail_log_validation(ct_client, account_id, timestamp):
    findings = []
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    for trail in trails:
        if not trail.get("LogFileValidationEnabled", False):
            trail_name = trail["Name"]
            finding = _make_finding(
                rule_id=f"cloudtrail-log-validation-{trail_name}",
                account_id=account_id,
                timestamp=timestamp,
                service="cloudtrail",
                severity="HIGH",
                resource_arn=trail.get("TrailARN", f"arn:aws:cloudtrail:{REGION}:{account_id}:trail/{trail_name}"),
                title="CloudTrail log file validation disabled",
                description=(
                    f"Trail '{trail_name}' does not have log file validation enabled. "
                    "Without this, log tampering or deletion cannot be detected."
                ),
            )
            finding["remediation"] = get_remediation(finding)
            findings.append(finding)
    return findings


def _check_cloudtrail_insights(ct_client, account_id, timestamp):
    findings = []
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    for trail in trails:
        trail_name = trail["Name"]
        trail_arn = trail.get("TrailARN", f"arn:aws:cloudtrail:{REGION}:{account_id}:trail/{trail_name}")
        try:
            selectors = ct_client.get_insight_selectors(TrailName=trail_arn).get("InsightSelectors", [])
            insights_enabled = bool(selectors)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InsightNotEnabledException":
                insights_enabled = False
            else:
                logger.warning("Could not check Insights for trail %s: %s", trail_name, e)
                continue

        if not insights_enabled:
            finding = _make_finding(
                rule_id=f"cloudtrail-insights-disabled-{trail_name}",
                account_id=account_id,
                timestamp=timestamp,
                service="cloudtrail",
                severity="MEDIUM",
                resource_arn=trail_arn,
                title="CloudTrail Insights not enabled",
                description=(
                    f"Trail '{trail_name}' does not have Insights selectors configured. "
                    "CloudTrail Insights detects unusual API call rates and error rates."
                ),
            )
            finding["remediation"] = get_remediation(finding)
            findings.append(finding)
    return findings


def _check_s3_public_access(s3_client, account_id, timestamp):
    findings = []
    buckets = s3_client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        try:
            config = s3_client.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            block_settings = {
                "BlockPublicAcls": config.get("BlockPublicAcls", False),
                "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": config.get("RestrictPublicBuckets", False),
            }
            missing = [k for k, v in block_settings.items() if not v]
            if missing:
                finding = _make_finding(
                    rule_id=f"s3-public-access-{name}",
                    account_id=account_id,
                    timestamp=timestamp,
                    service="s3",
                    severity="HIGH",
                    resource_arn=f"arn:aws:s3:::{name}",
                    title="S3 bucket public access not fully blocked",
                    description=f"Bucket '{name}' is missing public access block settings: {', '.join(missing)}.",
                )
                finding["remediation"] = get_remediation(finding)
                findings.append(finding)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                finding = _make_finding(
                    rule_id=f"s3-public-access-{name}",
                    account_id=account_id,
                    timestamp=timestamp,
                    service="s3",
                    severity="HIGH",
                    resource_arn=f"arn:aws:s3:::{name}",
                    title="S3 bucket has no public access block configuration",
                    description=f"Bucket '{name}' has no public access block configuration, leaving it potentially exposed.",
                )
                finding["remediation"] = get_remediation(finding)
                findings.append(finding)
            else:
                logger.warning("Could not check public access block for bucket %s: %s", name, e)
    return findings


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _calculate_scores(findings):
    deductions = {"iam": 0, "s3": 0, "cloudtrail": 0, "ec2": 0, "rds": 0}
    overall_deduction = 0
    critical_count = 0
    high_count = 0

    for f in findings:
        sev = f["severity"]
        svc = f["service"]
        d = SEVERITY_DEDUCTIONS.get(sev, 0)
        overall_deduction += d
        if svc in deductions:
            deductions[svc] += d
        if sev == "CRITICAL":
            critical_count += 1
        elif sev == "HIGH":
            high_count += 1

    def clamp(val):
        return max(0, 100 - val)

    return {
        "overall_score": clamp(overall_deduction),
        "iam_score": clamp(deductions["iam"]),
        "s3_score": clamp(deductions["s3"]),
        "cloudtrail_score": clamp(deductions["cloudtrail"]),
        "ec2_score": clamp(deductions["ec2"]),
        "rds_score": clamp(deductions["rds"]),
        "open_findings": len(findings),
        "critical_count": critical_count,
        "high_count": high_count,
    }


# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    timestamp = _now_iso()
    account_id = _get_account_id()
    triggered_by = "scheduled" if event.get("source") == "aws.events" else "manual"

    iam = boto3.client("iam", region_name=REGION)
    ct = boto3.client("cloudtrail", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    dynamodb = boto3.resource("dynamodb", region_name=REGION)
    findings_table = dynamodb.Table(TABLE_FINDINGS)
    posture_table = dynamodb.Table(TABLE_POSTURE)

    findings = []

    # IAM checks share one API call
    try:
        account_summary = iam.get_account_summary()["SummaryMap"]
        for check_fn in (_check_root_access_keys, _check_root_mfa):
            result = check_fn(account_summary, account_id, timestamp)
            if result:
                findings.append(result)
    except ClientError as e:
        logger.error("IAM account summary check failed: %s", e)

    # CloudTrail checks
    for check_fn in (_check_cloudtrail_log_validation, _check_cloudtrail_insights):
        try:
            findings.extend(check_fn(ct, account_id, timestamp))
        except ClientError as e:
            logger.error("%s failed: %s", check_fn.__name__, e)

    # S3 checks
    try:
        findings.extend(_check_s3_public_access(s3, account_id, timestamp))
    except ClientError as e:
        logger.error("S3 public access check failed: %s", e)

    # Write findings
    for finding in findings:
        try:
            findings_table.put_item(Item=finding)
            logger.info("Wrote finding: %s severity=%s", finding["finding_id"], finding["severity"])
        except ClientError as e:
            logger.error("Failed to write finding %s: %s", finding.get("finding_id"), e)

    # Write posture score
    scores = _calculate_scores(findings)
    scan_id = str(uuid.uuid4())
    posture_item = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "account_id": account_id,
        "triggered_by": triggered_by,
        **scores,
    }
    try:
        posture_table.put_item(Item=posture_item)
        logger.info(
            "Posture score written: scan_id=%s overall=%s critical=%s high=%s open=%s",
            scan_id, scores["overall_score"], scores["critical_count"],
            scores["high_count"], scores["open_findings"],
        )
    except ClientError as e:
        logger.error("Failed to write posture score: %s", e)

    return {
        "scan_id": scan_id,
        "findings_count": len(findings),
        "overall_score": scores["overall_score"],
        "critical_count": scores["critical_count"],
        "high_count": scores["high_count"],
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    result = lambda_handler({}, {})
    print(result)
