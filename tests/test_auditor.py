import os
import sys
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

# Fake credentials must be set before any boto3 import
os.environ.update({
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_SECURITY_TOKEN": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "DYNAMODB_TABLE_FINDINGS": "cloudguard-findings",
    "DYNAMODB_TABLE_POSTURE": "cloudguard-posture-scores",
})

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas"))

from auditor import (
    _check_cloudtrail_insights,
    _check_cloudtrail_log_validation,
    _check_root_access_keys,
    _check_root_mfa,
    _check_s3_public_access,
    lambda_handler,
)

ACCOUNT_ID = "123456789012"
TIMESTAMP = "2026-05-08T22:00:00Z"
REGION = "us-east-1"


@pytest.fixture(autouse=True)
def mock_get_remediation():
    with patch("auditor.get_remediation", return_value="mocked-remediation"):
        yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "operation")


def _mock_ct(trails, insight_selectors=None, insight_error_code=None):
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": trails}
    if insight_error_code:
        ct.get_insight_selectors.side_effect = _client_error(insight_error_code)
    else:
        ct.get_insight_selectors.return_value = {"InsightSelectors": insight_selectors or []}
    return ct


_TRAIL = {
    "Name": "test-trail",
    "TrailARN": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/test-trail",
    "LogFileValidationEnabled": False,
}


def _make_finding_stub(severity="CRITICAL", service="iam"):
    return {
        "finding_id": f"stub-{ACCOUNT_ID}-{TIMESTAMP}",
        "timestamp": TIMESTAMP,
        "account_id": ACCOUNT_ID,
        "region": REGION,
        "service": service,
        "severity": severity,
        "resource_arn": f"arn:aws:iam::{ACCOUNT_ID}:root",
        "title": "stub finding",
        "description": "desc",
        "remediation": "rem",
        "status": "OPEN",
        "source": "auditor",
    }


# ---------------------------------------------------------------------------
# Rule 1 — Root access keys
# ---------------------------------------------------------------------------

class TestCheckRootAccessKeys:
    def test_finding_when_keys_present(self):
        result = _check_root_access_keys(
            {"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 1},
            ACCOUNT_ID, TIMESTAMP,
        )
        assert result is not None
        assert result["severity"] == "CRITICAL"
        assert result["service"] == "iam"
        assert result["status"] == "OPEN"
        assert result["source"] == "auditor"
        assert ACCOUNT_ID in result["resource_arn"]
        assert ACCOUNT_ID in result["finding_id"]

    def test_pass_when_no_keys(self):
        result = _check_root_access_keys(
            {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1},
            ACCOUNT_ID, TIMESTAMP,
        )
        assert result is None

    def test_pass_when_key_field_missing(self):
        # Treat missing field as 0 (safe default)
        result = _check_root_access_keys({}, ACCOUNT_ID, TIMESTAMP)
        assert result is None


# ---------------------------------------------------------------------------
# Rule 2 — Root MFA
# ---------------------------------------------------------------------------

class TestCheckRootMFA:
    def test_finding_when_mfa_disabled(self):
        result = _check_root_mfa(
            {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 0},
            ACCOUNT_ID, TIMESTAMP,
        )
        assert result is not None
        assert result["severity"] == "CRITICAL"
        assert result["service"] == "iam"
        assert "MFA" in result["title"]

    def test_pass_when_mfa_enabled(self):
        result = _check_root_mfa(
            {"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1},
            ACCOUNT_ID, TIMESTAMP,
        )
        assert result is None

    def test_pass_when_mfa_field_missing(self):
        # Missing field defaults to 1 (enabled) — safe default in the implementation
        result = _check_root_mfa({}, ACCOUNT_ID, TIMESTAMP)
        assert result is None


# ---------------------------------------------------------------------------
# Rule 3 — CloudTrail log file validation
# ---------------------------------------------------------------------------

class TestCheckCloudTrailLogValidation:
    def test_finding_when_validation_disabled(self):
        ct = _mock_ct([_TRAIL])
        findings = _check_cloudtrail_log_validation(ct, ACCOUNT_ID, TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["service"] == "cloudtrail"
        assert "test-trail" in findings[0]["finding_id"]
        assert "test-trail" in findings[0]["description"]
        assert findings[0]["status"] == "OPEN"

    def test_pass_when_validation_enabled(self):
        ct = _mock_ct([{**_TRAIL, "LogFileValidationEnabled": True}])
        findings = _check_cloudtrail_log_validation(ct, ACCOUNT_ID, TIMESTAMP)
        assert findings == []

    def test_multiple_trails_each_checked(self):
        trails = [
            {**_TRAIL, "Name": "trail-a", "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/trail-a", "LogFileValidationEnabled": False},
            {**_TRAIL, "Name": "trail-b", "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/trail-b", "LogFileValidationEnabled": True},
        ]
        ct = _mock_ct(trails)
        findings = _check_cloudtrail_log_validation(ct, ACCOUNT_ID, TIMESTAMP)
        assert len(findings) == 1
        assert "trail-a" in findings[0]["finding_id"]

    def test_no_trails_returns_no_findings(self):
        ct = _mock_ct([])
        assert _check_cloudtrail_log_validation(ct, ACCOUNT_ID, TIMESTAMP) == []


# ---------------------------------------------------------------------------
# Rule 4 — CloudTrail Insights
# ---------------------------------------------------------------------------

class TestCheckCloudTrailInsights:
    def test_finding_when_insights_never_configured(self):
        ct = _mock_ct([_TRAIL], insight_error_code="InsightNotEnabledException")
        findings = _check_cloudtrail_insights(ct, ACCOUNT_ID, TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"
        assert findings[0]["service"] == "cloudtrail"
        assert findings[0]["status"] == "OPEN"

    def test_finding_when_insight_selectors_empty(self):
        ct = _mock_ct([_TRAIL], insight_selectors=[])
        findings = _check_cloudtrail_insights(ct, ACCOUNT_ID, TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["severity"] == "MEDIUM"

    def test_pass_when_insights_configured(self):
        ct = _mock_ct([_TRAIL], insight_selectors=[{"InsightType": "ApiCallRateInsight"}])
        findings = _check_cloudtrail_insights(ct, ACCOUNT_ID, TIMESTAMP)
        assert findings == []

    def test_unexpected_client_error_is_skipped(self):
        ct = _mock_ct([_TRAIL], insight_error_code="AccessDeniedException")
        # should not raise — the error is logged and the trail is skipped
        findings = _check_cloudtrail_insights(ct, ACCOUNT_ID, TIMESTAMP)
        assert findings == []

    def test_no_trails_returns_no_findings(self):
        ct = _mock_ct([])
        assert _check_cloudtrail_insights(ct, ACCOUNT_ID, TIMESTAMP) == []


# ---------------------------------------------------------------------------
# Rule 5 — S3 public access block
# ---------------------------------------------------------------------------

@mock_aws
class TestCheckS3PublicAccess:
    def _s3(self):
        return boto3.client("s3", region_name=REGION)

    def _create_bucket(self, s3, name):
        s3.create_bucket(Bucket=name)

    def _block_all(self, s3, name):
        s3.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

    def test_finding_when_no_block_config(self):
        s3 = self._s3()
        self._create_bucket(s3, "unprotected-bucket")
        findings = _check_s3_public_access(s3, ACCOUNT_ID, TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["service"] == "s3"
        assert "arn:aws:s3:::unprotected-bucket" == findings[0]["resource_arn"]

    def test_finding_when_partial_block(self):
        s3 = self._s3()
        self._create_bucket(s3, "partial-bucket")
        s3.put_public_access_block(
            Bucket="partial-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            },
        )
        findings = _check_s3_public_access(s3, ACCOUNT_ID, TIMESTAMP)
        assert len(findings) == 1
        assert "IgnorePublicAcls" in findings[0]["description"]
        assert "RestrictPublicBuckets" in findings[0]["description"]

    def test_pass_when_all_blocks_enabled(self):
        s3 = self._s3()
        self._create_bucket(s3, "protected-bucket")
        self._block_all(s3, "protected-bucket")
        findings = _check_s3_public_access(s3, ACCOUNT_ID, TIMESTAMP)
        assert findings == []

    def test_empty_account_has_no_findings(self):
        s3 = self._s3()
        assert _check_s3_public_access(s3, ACCOUNT_ID, TIMESTAMP) == []

    def test_mixed_buckets_only_flags_unprotected(self):
        s3 = self._s3()
        self._create_bucket(s3, "safe-bucket")
        self._block_all(s3, "safe-bucket")
        self._create_bucket(s3, "unsafe-bucket")
        findings = _check_s3_public_access(s3, ACCOUNT_ID, TIMESTAMP)
        assert len(findings) == 1
        assert findings[0]["resource_arn"] == "arn:aws:s3:::unsafe-bucket"


# ---------------------------------------------------------------------------
# Lambda handler integration
# ---------------------------------------------------------------------------

def _create_tables(ddb):
    for table_name, pk in [("cloudguard-findings", "finding_id"), ("cloudguard-posture-scores", "scan_id")]:
        ddb.create_table(
            TableName=table_name,
            AttributeDefinitions=[
                {"AttributeName": pk, "AttributeType": "S"},
                {"AttributeName": "timestamp", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": pk, "KeyType": "HASH"},
                {"AttributeName": "timestamp", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )


@mock_aws
class TestLambdaHandler:
    def _setup(self):
        ddb = boto3.resource("dynamodb", region_name=REGION)
        _create_tables(ddb)
        return ddb

    def _run(self, event=None, findings_by_check=None):
        defaults = {
            "auditor._check_root_access_keys": None,
            "auditor._check_root_mfa": None,
            "auditor._check_cloudtrail_log_validation": [],
            "auditor._check_cloudtrail_insights": [],
            "auditor._check_s3_public_access": [],
        }
        overrides = {f"auditor.{k}": v for k, v in (findings_by_check or {}).items()}
        patches = {**defaults, **overrides}

        with (
            patch("auditor._get_account_id", return_value=ACCOUNT_ID),
            patch("auditor._check_root_access_keys", return_value=patches["auditor._check_root_access_keys"]),
            patch("auditor._check_root_mfa", return_value=patches["auditor._check_root_mfa"]),
            patch("auditor._check_cloudtrail_log_validation", return_value=patches["auditor._check_cloudtrail_log_validation"]),
            patch("auditor._check_cloudtrail_insights", return_value=patches["auditor._check_cloudtrail_insights"]),
            patch("auditor._check_s3_public_access", return_value=patches["auditor._check_s3_public_access"]),
        ):
            return lambda_handler(event or {}, {})

    def test_critical_finding_written_to_dynamodb(self):
        ddb = self._setup()
        finding = _make_finding_stub("CRITICAL", "iam")

        result = self._run(findings_by_check={"_check_root_access_keys": finding})

        assert result["findings_count"] == 1
        assert result["critical_count"] == 1
        assert result["overall_score"] == 75  # 100 - 25

        items = ddb.Table("cloudguard-findings").scan()["Items"]
        assert len(items) == 1
        assert items[0]["severity"] == "CRITICAL"
        assert items[0]["source"] == "auditor"

    def test_posture_score_written_to_dynamodb(self):
        ddb = self._setup()
        finding = _make_finding_stub("HIGH", "s3")

        self._run(findings_by_check={"_check_s3_public_access": [finding]})

        scores = ddb.Table("cloudguard-posture-scores").scan()["Items"]
        assert len(scores) == 1
        assert scores[0]["overall_score"] == 90  # 100 - 10
        assert scores[0]["high_count"] == 1
        assert scores[0]["account_id"] == ACCOUNT_ID

    def test_no_findings_gives_perfect_score(self):
        ddb = self._setup()
        result = self._run()

        assert result["findings_count"] == 0
        assert result["overall_score"] == 100
        assert result["critical_count"] == 0

        scores = ddb.Table("cloudguard-posture-scores").scan()["Items"]
        assert scores[0]["overall_score"] == 100

    def test_score_clamped_at_zero_for_many_findings(self):
        self._setup()
        many_criticals = [_make_finding_stub("CRITICAL", "iam") for _ in range(10)]

        result = self._run(findings_by_check={"_check_cloudtrail_log_validation": many_criticals})

        assert result["overall_score"] == 0  # clamped, not negative

    def test_eventbridge_trigger_sets_scheduled(self):
        ddb = self._setup()
        self._run(event={"source": "aws.events"})

        scores = ddb.Table("cloudguard-posture-scores").scan()["Items"]
        assert scores[0]["triggered_by"] == "scheduled"

    def test_manual_trigger_sets_manual(self):
        ddb = self._setup()
        self._run(event={})

        scores = ddb.Table("cloudguard-posture-scores").scan()["Items"]
        assert scores[0]["triggered_by"] == "manual"
