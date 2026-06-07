"""Prompt builder for Gemini log analysis. Caps at 150 log lines."""

from __future__ import annotations

from src.utils.log_parser import ParsedEvent

MAX_LINES = 150

SYSTEM_PROMPT = """You are an expert Site Reliability Engineer (SRE) and cloud infrastructure specialist.
Analyze the provided AWS CloudWatch logs or alarm data and return ONLY a valid JSON object.

Your analysis must be precise, actionable, and production-focused. Base your assessment strictly on the evidence in the logs."""

RESPONSE_SCHEMA = """{
  "summary": "<one-sentence description of the incident>",
  "root_cause": "<technical root cause based on log evidence>",
  "severity": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "affected_components": ["<service/component names>"],
  "recommended_actions": ["<immediate action>", "<follow-up action>", "..."],
  "error_patterns": ["<recurring error pattern>", "..."],
  "anomalies": ["<unusual behavior observed>", "..."]
}"""


def build_prompt(parsed: ParsedEvent) -> str:
    lines = parsed.log_lines[:MAX_LINES]
    log_block = "\n".join(lines) if lines else "(no log lines available)"

    source_context = ""
    if parsed.source == "sns_alarm":
        source_context = f"""
**Trigger Type:** CloudWatch Alarm
**Alarm Name:** {parsed.alarm_name}
**Alarm State:** {parsed.alarm_state}
**Description:** {parsed.alarm_description}
"""
    else:
        meta = parsed.metadata
        source_context = f"""
**Trigger Type:** CloudWatch Logs Subscription Filter
**Total Log Events:** {meta.get("total_events", len(lines))}
**Error Events:** {meta.get("error_events", "N/A")}
**Subscription Filters:** {", ".join(meta.get("subscription_filters", []))}
"""

    prompt = f"""Analyze the following AWS CloudWatch data and return ONLY a JSON object matching the schema below.

## Context
**Log Group:** {parsed.log_group}
**Log Stream:** {parsed.log_stream}
{source_context}

## Log Data ({len(lines)} lines, error lines prioritized)
```
{log_block}
```

## Required Response Schema
```json
{RESPONSE_SCHEMA}
```

Rules:
- severity must be exactly one of: LOW, MEDIUM, HIGH, CRITICAL
- recommended_actions must contain at least 3 specific, actionable steps
- All arrays must have at least 1 element
- Return ONLY the JSON object, no explanation or markdown wrapper"""

    return prompt
