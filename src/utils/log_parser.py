"""
CloudWatch Logs event parsing with error-first prioritization.
Supports both direct CWL subscription filter events and SNS-wrapped alarm events.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
from dataclasses import dataclass, field
from typing import Any

MAX_ERROR_LINES = 80
MAX_NORMAL_LINES = 70
MAX_TOTAL_LINES = MAX_ERROR_LINES + MAX_NORMAL_LINES

ERROR_PATTERN = re.compile(
    r"\b(error|exception|traceback|critical|fatal|fail(?:ed|ure)?|panic|crash)\b",
    re.IGNORECASE,
)

SEVERITY_KEYWORDS = {
    "CRITICAL": ["critical", "fatal", "panic", "crash"],
    "HIGH": ["error", "exception", "traceback", "fail"],
    "MEDIUM": ["warn", "warning", "timeout", "retry"],
    "LOW": ["info", "debug", "notice"],
}


@dataclass
class ParsedEvent:
    source: str  # "sns_alarm" | "cwl_subscription"
    log_group: str
    log_stream: str
    log_lines: list[str]
    alarm_name: str = ""
    alarm_description: str = ""
    alarm_state: str = ""
    raw_message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def _decode_cwl_data(data: str) -> dict[str, Any]:
    compressed = base64.b64decode(data)
    return json.loads(gzip.decompress(compressed).decode("utf-8"))


def _prioritize_lines(lines: list[str]) -> list[str]:
    error_lines = [line for line in lines if ERROR_PATTERN.search(line)]
    normal_lines = [line for line in lines if not ERROR_PATTERN.search(line)]
    return error_lines[:MAX_ERROR_LINES] + normal_lines[:MAX_NORMAL_LINES]


def _extract_cwl_lines(cwl_data: dict[str, Any]) -> list[str]:
    events = cwl_data.get("logEvents", [])
    return [e.get("message", "").strip() for e in events if e.get("message")]


def parse_sns_alarm(record: dict[str, Any]) -> ParsedEvent:
    body = json.loads(record["Sns"]["Message"])
    alarm_name = body.get("AlarmName", "unknown-alarm")
    alarm_description = body.get("AlarmDescription", "")
    alarm_state = body.get("NewStateValue", "ALARM")
    trigger = body.get("Trigger", {})
    log_group = (
        trigger.get("Dimensions", [{}])[0].get("value", "") if trigger.get("Dimensions") else ""
    )
    raw_message = json.dumps(body, indent=2)
    lines = [
        f"ALARM: {alarm_name}",
        f"State: {alarm_state}",
        f"Description: {alarm_description}",
        f"Reason: {body.get('NewStateReason', '')}",
        f"Metric: {trigger.get('MetricName', '')}",
        f"Namespace: {trigger.get('Namespace', '')}",
        f"Threshold: {trigger.get('Threshold', '')}",
        f"Period: {trigger.get('Period', '')}s",
        f"Statistic: {trigger.get('Statistic', '')}",
    ]
    return ParsedEvent(
        source="sns_alarm",
        log_group=log_group or f"alarm/{alarm_name}",
        log_stream="cloudwatch-alarm",
        log_lines=lines,
        alarm_name=alarm_name,
        alarm_description=alarm_description,
        alarm_state=alarm_state,
        raw_message=raw_message,
        metadata={"trigger": trigger},
    )


def parse_cwl_subscription(record: dict[str, Any]) -> ParsedEvent:
    cwl_data = _decode_cwl_data(record["awslogs"]["data"])
    log_group = cwl_data.get("logGroup", "unknown")
    log_stream = cwl_data.get("logStream", "unknown")
    all_lines = _extract_cwl_lines(cwl_data)
    prioritized = _prioritize_lines(all_lines)
    return ParsedEvent(
        source="cwl_subscription",
        log_group=log_group,
        log_stream=log_stream,
        log_lines=prioritized,
        raw_message=json.dumps(cwl_data, indent=2),
        metadata={
            "subscription_filters": cwl_data.get("subscriptionFilters", []),
            "total_events": len(all_lines),
            "error_events": len([ln for ln in all_lines if ERROR_PATTERN.search(ln)]),
        },
    )


def detect_event_type(event: dict[str, Any]) -> str:
    records = event.get("Records", [])
    if records:
        first = records[0]
        if "Sns" in first:
            return "sns_alarm"
        if "awslogs" in first:
            return "cwl_subscription"
    if "awslogs" in event:
        return "cwl_direct"
    return "unknown"


def parse_event(event: dict[str, Any]) -> list[ParsedEvent]:
    event_type = detect_event_type(event)
    parsed = []

    if event_type == "sns_alarm":
        for record in event.get("Records", []):
            parsed.append(parse_sns_alarm(record))

    elif event_type in ("cwl_subscription", "cwl_direct"):
        records = event.get("Records", [event]) if event_type == "cwl_subscription" else [event]
        for record in records:
            cwl_record = record if "awslogs" in record else {"awslogs": record.get("awslogs", {})}
            if cwl_record.get("awslogs", {}).get("data"):
                parsed.append(parse_cwl_subscription(cwl_record))

    return parsed


def infer_severity(lines: list[str]) -> str:
    text = " ".join(lines).lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            return severity
    return "LOW"
