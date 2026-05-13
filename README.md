# CloudGuard

Automated cloud security posture management and threat detection platform on AWS.

## Overview

CloudGuard continuously audits your AWS environment for misconfigurations, ingests CloudTrail events for threat detection, and delivers real-time alerts via Telegram. Posture scores are stored in DynamoDB and threat analysis is powered by Gemini AI.

## Architecture

```
CloudTrail → S3/EventBridge → Lambda (Ingestor)
                                      ↓
                             Lambda (Auditor) ← Scheduled
                                      ↓
                              Gemini AI Analysis
                                      ↓
                           DynamoDB (Posture Scores)
                                      ↓
                           Lambda (Alerter) → Telegram
```

## Components

| Component | Description |
|-----------|-------------|
| `lambdas/auditor.py` | Scans AWS resources for misconfigurations (S3, IAM, SGs, etc.) |
| `lambdas/ingestor.py` | Consumes CloudTrail events and detects anomalous activity |
| `lambdas/alerter.py` | Sends formatted Telegram alerts for findings |
| `lambdas/scorer.py` | Calculates and persists posture scores to DynamoDB |

## Setup

1. Copy `.env.example` to `.env` and fill in credentials
2. `pip install -r requirements.txt`
3. Deploy via AWS SAM or CDK (see `/infra`)

## Requirements

- AWS account with CloudTrail enabled
- Telegram Bot token + chat ID
- Google Gemini API key
- Python 3.11+
