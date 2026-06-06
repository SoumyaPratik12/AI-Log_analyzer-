"""
SNS (email/SMS) and Slack notification formatters.
SNS uses boto3 directly — no extra dependencies.
Slack uses stdlib urllib only.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

import boto3

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}

SEVERITY_COLOR = {
    "CRITICAL": "#FF0000",
    "HIGH": "#FF6600",
    "MEDIUM": "#FFCC00",
    "LOW": "#36A64F",
}

SNS_TOPIC_ARN_ENV = "ALERT_SNS_TOPIC_ARN"
SLACK_WEBHOOK_SSM = "SLACK_WEBHOOK_URL_SSM_PATH"

_ssm_cache: dict[str, str] = {}


def _get_ssm_value(ssm_path_env: str) -> str:
    ssm_path = os.environ.get(ssm_path_env)
    if not ssm_path:
        raise OSError(f"Environment variable {ssm_path_env} is not set")
    if ssm_path in _ssm_cache:
        return _ssm_cache[ssm_path]

    ssm = boto3.client("ssm", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
    response = ssm.get_parameter(Name=ssm_path, WithDecryption=True)
    value = response["Parameter"]["Value"]
    _ssm_cache[ssm_path] = value
    return value


def _http_post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        logger.error("HTTP %d from %s: %s", e.code, url, body)
        raise
    except urllib.error.URLError as e:
        logger.error("URL error posting to %s: %s", url, e.reason)
        raise


def _format_sns_message(analysis: dict[str, Any], log_group: str, source: str) -> tuple[str, str]:
    """Returns (subject, body) for SNS publish."""
    severity = analysis.get("severity", "UNKNOWN")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")

    actions = "\n".join(
        f"  {i + 1}. {a}" for i, a in enumerate(analysis.get("recommended_actions", []))
    )
    components = ", ".join(analysis.get("affected_components", []))
    patterns = "\n".join(f"  - {p}" for p in analysis.get("error_patterns", []))
    anomalies = "\n".join(f"  - {a}" for a in analysis.get("anomalies", []))

    subject = f"{emoji} [{severity}] AI Log Alert: {log_group}"[:100]

    body = (
        f"{emoji} AI Log Analysis Alert\n"
        f"{'=' * 50}\n\n"
        f"Severity : {severity}\n"
        f"Source   : {source}\n"
        f"Log Group: {log_group}\n\n"
        f"SUMMARY\n{analysis.get('summary', 'N/A')}\n\n"
        f"ROOT CAUSE\n{analysis.get('root_cause', 'N/A')}\n\n"
        f"AFFECTED COMPONENTS\n{components}\n\n"
        f"RECOMMENDED ACTIONS\n{actions}\n\n"
        f"ERROR PATTERNS\n{patterns}\n\n"
        f"ANOMALIES\n{anomalies}"
    )
    return subject, body


def send_sns(analysis: dict[str, Any], log_group: str, source: str) -> bool:
    try:
        topic_arn = os.environ.get(SNS_TOPIC_ARN_ENV)
        if not topic_arn:
            raise OSError(f"{SNS_TOPIC_ARN_ENV} is not set")

        subject, body = _format_sns_message(analysis, log_group, source)
        sns = boto3.client("sns", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
        sns.publish(TopicArn=topic_arn, Subject=subject, Message=body)
        logger.info("SNS notification sent to %s", topic_arn)
        return True
    except Exception as e:
        logger.error("Failed to send SNS notification: %s", e)
        return False


def _build_slack_blocks(analysis: dict[str, Any], log_group: str, source: str) -> list[dict]:
    severity = analysis.get("severity", "UNKNOWN")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    color = SEVERITY_COLOR.get(severity, "#808080")

    actions_text = "\n".join(
        f"{i + 1}. {a}" for i, a in enumerate(analysis.get("recommended_actions", []))
    )
    components = ", ".join(analysis.get("affected_components", []))
    patterns_text = "\n".join(f"• {p}" for p in analysis.get("error_patterns", []))
    anomalies_text = "\n".join(f"• {a}" for a in analysis.get("anomalies", []))

    return [
        {
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} AI Log Analysis Alert — {severity}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                        {"type": "mrkdwn", "text": f"*Source:*\n{source}"},
                        {"type": "mrkdwn", "text": f"*Log Group:*\n`{log_group}`"},
                    ],
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Summary*\n{analysis.get('summary', 'N/A')}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Root Cause*\n{analysis.get('root_cause', 'N/A')}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Affected Components*\n{components}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Recommended Actions*\n{actions_text}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Error Patterns*\n{patterns_text}"},
                        {"type": "mrkdwn", "text": f"*Anomalies*\n{anomalies_text}"},
                    ],
                },
            ],
        }
    ]


def send_slack(analysis: dict[str, Any], log_group: str, source: str) -> bool:
    try:
        webhook_url = _get_ssm_value(SLACK_WEBHOOK_SSM)
        attachments = _build_slack_blocks(analysis, log_group, source)
        payload = {"attachments": attachments}
        _http_post(webhook_url, payload)
        logger.info("Slack notification sent successfully")
        return True
    except Exception as e:
        logger.error("Failed to send Slack notification: %s", e)
        return False


def send_notifications(analysis: dict[str, Any], log_group: str, source: str) -> dict[str, bool]:
    results = {
        "sns": send_sns(analysis, log_group, source),
        "slack": send_slack(analysis, log_group, source),
    }
    logger.info("Notification results: %s", results)
    return results
