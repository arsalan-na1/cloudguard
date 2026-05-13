import logging
import os

from google import genai

logger = logging.getLogger(__name__)

_MODEL = "gemini-2.5-flash"
_FALLBACK = (
    "Review the finding description and consult the AWS documentation for this service. "
    "Apply the principle of least privilege and enable all recommended security controls."
)
_PROMPT = """\
You are a cloud security engineer reviewing an AWS misconfiguration finding.

Finding:
  Title:       {title}
  Severity:    {severity}
  Service:     {service}
  Resource:    {resource_arn}
  Description: {description}

Write a 2-3 sentence plain-English remediation recommendation. \
Include the exact AWS CLI command or specific AWS console navigation steps \
needed to resolve this issue. Be concise and actionable.
"""


def get_remediation(finding: dict) -> str:
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        logger.warning("GEMINI_API_KEY not set — returning fallback remediation")
        return _FALLBACK

    prompt = _PROMPT.format(
        title=finding.get("title", "Unknown"),
        severity=finding.get("severity", "Unknown"),
        service=finding.get("service", "Unknown"),
        resource_arn=finding.get("resource_arn", "Unknown"),
        description=finding.get("description", "No description provided"),
    )

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=_MODEL, contents=prompt)
        return response.text.strip()
    except Exception as e:
        logger.warning("Gemini API call failed (%s) — returning fallback remediation", e)
        return _FALLBACK
