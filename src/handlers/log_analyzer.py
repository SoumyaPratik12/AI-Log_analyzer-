"""
Lambda entry point — handles both SNS alarm triggers and CWL subscription filter events.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from src.prompts.analysis_prompt import SYSTEM_PROMPT, build_prompt
from src.utils.claude_client import analyze_logs
from src.utils.log_parser import ParsedEvent, parse_event
from src.utils.notifier import send_notifications

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def _process_parsed_event(parsed: ParsedEvent) -> dict[str, Any]:
    logger.info(
        "Processing event: source=%s log_group=%s lines=%d",
        parsed.source,
        parsed.log_group,
        len(parsed.log_lines),
    )

    user_prompt = build_prompt(parsed)
    analysis = analyze_logs(SYSTEM_PROMPT, user_prompt)

    logger.info(
        "Analysis complete: severity=%s summary=%s",
        analysis.get("severity"),
        analysis.get("summary", "")[:80],
    )

    notify_results = send_notifications(analysis, parsed.log_group, parsed.source)

    return {
        "log_group": parsed.log_group,
        "log_stream": parsed.log_stream,
        "source": parsed.source,
        "analysis": analysis,
        "notifications": notify_results,
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    logger.info("Lambda invoked with event keys: %s", list(event.keys()))

    try:
        parsed_events = parse_event(event)
    except Exception as e:
        logger.error("Failed to parse event: %s", e, exc_info=True)
        return {"statusCode": 400, "results": [], "errors": [{"error": str(e)}]}

    if not parsed_events:
        logger.warning("No parseable events found in input")
        return {"statusCode": 200, "message": "No events to process", "results": []}

    results = []
    errors = []

    for parsed in parsed_events:
        try:
            result = _process_parsed_event(parsed)
            results.append(result)
        except Exception as e:
            logger.error(
                "Error processing event from %s/%s: %s",
                parsed.log_group,
                parsed.log_stream,
                e,
                exc_info=True,
            )
            errors.append(
                {
                    "log_group": parsed.log_group,
                    "source": parsed.source,
                    "error": str(e),
                }
            )

    response: dict[str, Any] = {
        "statusCode": 200 if not errors else 207,
        "results": results,
    }
    if errors:
        response["errors"] = errors

    logger.info(
        "Lambda complete: processed=%d errors=%d",
        len(results),
        len(errors),
    )
    return response
