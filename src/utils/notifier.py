"""
Telegram and Slack notification formatters using only stdlib urllib.
No third-party HTTP libraries required.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

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

TELEGRAM_BOT_TOKEN_SSM = "TELEGRAM_BOT_TOKEN_SSM_PATH"
TELEGRAM_CHAT_ID_ENV = "TELEGRAM_CHAT_ID"
SLACK_WEBHOOK_SSM = "SLACK_WEBHOOK_URL_SSM_PATH"

_ssm_cache: dict[str, str] = {}


def _get_ssm_value(ssm_path_env: str) -> str:
    ssm_path = os.environ.get(ssm_path_env)
    if not ssm_path:
        raise OSError(f"Environment variable {ssm_path_env} is not set")
    if ssm_path in _ssm_cache:
        return _ssm_cache[ssm_path]

    import boto3

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


def _format_telegram_message(analysis: dict[str, Any], log_group: str, source: str) -> str:
    severity = analysis.get("severity", "UNKNOWN")
    emoji = SEVERITY_EMOJI.get(severity, "⚪")

    actions = "\n".join(
        f"  {i + 1}. {a}" for i, a in enumerate(analysis.get("recommended_actions", []))
    )
    components = ", ".join(analysis.get("affected_components", []))
    patterns = "\n".join(f"  • {p}" for p in analysis.get("error_patterns", []))
    anomalies = "\n".join(f"  • {a}" for a in analysis.get("anomalies", []))

    return (
        f"{emoji} <b>AI Log Analysis Alert</b> {emoji}\n\n"
        f"<b>Severity:</b> {severity}\n"
        f"<b>Source:</b> {source}\n"
        f"<b>Log Group:</b> <code>{log_group}</code>\n\n"
        f"<b>Summary:</b>\n{analysis.get('summary', 'N/A')}\n\n"
        f"<b>Root Cause:</b>\n{analysis.get('root_cause', 'N/A')}\n\n"
        f"<b>Affected Components:</b> {components}\n\n"
        f"<b>Recommended Actions:</b>\n{actions}\n\n"
        f"<b>Error Patterns:</b>\n{patterns}\n\n"
        f"<b>Anomalies:</b>\n{anomalies}"
    )


def send_telegram(analysis: dict[str, Any], log_group: str, source: str) -> bool:
    try:
        bot_token = _get_ssm_value(TELEGRAM_BOT_TOKEN_SSM)
        chat_id = os.environ.get(TELEGRAM_CHAT_ID_ENV)
        if not chat_id:
            raise OSError(f"{TELEGRAM_CHAT_ID_ENV} is not set")

        message = _format_telegram_message(analysis, log_group, source)
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        result = _http_post(url, payload)
        if result.get("ok"):
            logger.info("Telegram notification sent successfully")
            return True
        logger.error("Telegram API returned ok=false: %s", result)
        return False
    except Exception as e:
        logger.error("Failed to send Telegram notification: %s", e)
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
        "telegram": send_telegram(analysis, log_group, source),
        "slack": send_slack(analysis, log_group, source),
    }
    logger.info("Notification results: %s", results)
    return results
