"""
Unit tests for log_parser, analysis_prompt, and handler.
All AWS and Claude API calls are mocked.
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------


def _cwl_data(log_group: str = "/aws/lambda/my-fn", events: list[str] | None = None) -> str:
    if events is None:
        events = [
            "2024-01-01T00:00:00Z START RequestId: abc",
            "2024-01-01T00:00:01Z ERROR Exception: NullPointerException at line 42",
            "2024-01-01T00:00:01Z TRACEBACK: ...",
            "2024-01-01T00:00:02Z END RequestId: abc",
        ]
    payload = {
        "messageType": "DATA_MESSAGE",
        "owner": "123456789",
        "logGroup": log_group,
        "logStream": "2024/01/01/[$LATEST]abc",
        "subscriptionFilters": ["ErrorFilter"],
        "logEvents": [{"id": str(i), "timestamp": i, "message": m} for i, m in enumerate(events)],
    }
    compressed = gzip.compress(json.dumps(payload).encode())
    return base64.b64encode(compressed).decode()


def _sns_alarm_event(alarm_name: str = "HighErrorRate") -> dict[str, Any]:
    message = {
        "AlarmName": alarm_name,
        "AlarmDescription": "Error rate exceeded threshold",
        "NewStateValue": "ALARM",
        "NewStateReason": "Threshold Crossed: 5 datapoints > 10.0",
        "Trigger": {
            "MetricName": "Errors",
            "Namespace": "AWS/Lambda",
            "Statistic": "Sum",
            "Threshold": 10.0,
            "Period": 60,
            "Dimensions": [{"name": "FunctionName", "value": "/aws/lambda/my-fn"}],
        },
    }
    return {
        "Records": [
            {
                "Sns": {
                    "Message": json.dumps(message),
                    "Subject": "ALARM: HighErrorRate",
                }
            }
        ]
    }


def _cwl_subscription_event(log_group: str = "/aws/lambda/my-fn") -> dict[str, Any]:
    return {"Records": [{"awslogs": {"data": _cwl_data(log_group)}}]}


MOCK_ANALYSIS = {
    "summary": "Lambda function experiencing NullPointerException causing request failures",
    "root_cause": "Unhandled NullPointerException at line 42 due to missing input validation",
    "severity": "HIGH",
    "affected_components": ["my-fn Lambda", "downstream API"],
    "recommended_actions": [
        "Add null checks before accessing object at line 42",
        "Review input validation for all incoming requests",
        "Add CloudWatch alarm for sustained error rate",
    ],
    "error_patterns": ["NullPointerException at line 42"],
    "anomalies": ["Spike in error rate within 2-second window"],
}


# ---------------------------------------------------------------------------
# log_parser tests
# ---------------------------------------------------------------------------


class TestLogParser:
    def test_detect_sns_event_type(self):
        from src.utils.log_parser import detect_event_type

        event = _sns_alarm_event()
        assert detect_event_type(event) == "sns_alarm"

    def test_detect_cwl_event_type(self):
        from src.utils.log_parser import detect_event_type

        event = _cwl_subscription_event()
        assert detect_event_type(event) == "cwl_subscription"

    def test_detect_unknown_event_type(self):
        from src.utils.log_parser import detect_event_type

        assert detect_event_type({"foo": "bar"}) == "unknown"

    def test_parse_sns_alarm(self):
        from src.utils.log_parser import parse_event

        events = parse_event(_sns_alarm_event())
        assert len(events) == 1
        e = events[0]
        assert e.source == "sns_alarm"
        assert e.alarm_name == "HighErrorRate"
        assert e.alarm_state == "ALARM"
        assert len(e.log_lines) > 0

    def test_parse_cwl_subscription(self):
        from src.utils.log_parser import parse_event

        events = parse_event(_cwl_subscription_event())
        assert len(events) == 1
        e = events[0]
        assert e.source == "cwl_subscription"
        assert e.log_group == "/aws/lambda/my-fn"
        assert len(e.log_lines) > 0

    def test_error_lines_prioritized(self):
        from src.utils.log_parser import parse_event

        mixed_events = [f"INFO normal line {i}" for i in range(100)]
        mixed_events += [f"ERROR bad line {i}" for i in range(10)]
        event = {"Records": [{"awslogs": {"data": _cwl_data(events=mixed_events)}}]}
        parsed = parse_event(event)[0]
        # Error lines should appear first
        error_indices = [i for i, ln in enumerate(parsed.log_lines) if "ERROR" in ln]
        normal_indices = [i for i, ln in enumerate(parsed.log_lines) if "INFO" in ln]
        if error_indices and normal_indices:
            assert max(error_indices) < min(normal_indices) or error_indices[0] < normal_indices[-1]

    def test_max_150_lines_respected(self):
        from src.utils.log_parser import MAX_TOTAL_LINES, parse_event

        large_events = [f"INFO line {i}" for i in range(300)]
        event = {"Records": [{"awslogs": {"data": _cwl_data(events=large_events)}}]}
        parsed = parse_event(event)[0]
        assert len(parsed.log_lines) <= MAX_TOTAL_LINES

    def test_error_first_max_80_error_lines(self):
        from src.utils.log_parser import MAX_ERROR_LINES, parse_event

        error_events = [f"ERROR bad thing {i}" for i in range(120)]
        event = {"Records": [{"awslogs": {"data": _cwl_data(events=error_events)}}]}
        parsed = parse_event(event)[0]
        error_count = sum(1 for ln in parsed.log_lines if "ERROR" in ln)
        assert error_count <= MAX_ERROR_LINES

    def test_infer_severity_critical(self):
        from src.utils.log_parser import infer_severity

        assert infer_severity(["CRITICAL system failure"]) == "CRITICAL"

    def test_infer_severity_low(self):
        from src.utils.log_parser import infer_severity

        assert infer_severity(["INFO all good", "DEBUG checking values"]) == "LOW"

    def test_decode_cwl_data(self):
        from src.utils.log_parser import _decode_cwl_data

        data = _cwl_data()
        result = _decode_cwl_data(data)
        assert result["logGroup"] == "/aws/lambda/my-fn"
        assert len(result["logEvents"]) > 0


# ---------------------------------------------------------------------------
# analysis_prompt tests
# ---------------------------------------------------------------------------


class TestAnalysisPrompt:
    def _get_cwl_parsed(self):
        from src.utils.log_parser import parse_event

        return parse_event(_cwl_subscription_event())[0]

    def _get_sns_parsed(self):
        from src.utils.log_parser import parse_event

        return parse_event(_sns_alarm_event())[0]

    def test_prompt_contains_log_group(self):
        from src.prompts.analysis_prompt import build_prompt

        parsed = self._get_cwl_parsed()
        prompt = build_prompt(parsed)
        assert "/aws/lambda/my-fn" in prompt

    def test_prompt_contains_log_lines(self):
        from src.prompts.analysis_prompt import build_prompt

        parsed = self._get_cwl_parsed()
        prompt = build_prompt(parsed)
        assert "NullPointerException" in prompt or "ERROR" in prompt or "START" in prompt

    def test_prompt_max_150_lines(self):
        from src.prompts.analysis_prompt import MAX_LINES, build_prompt
        from src.utils.log_parser import ParsedEvent

        parsed = ParsedEvent(
            source="cwl_subscription",
            log_group="/test",
            log_stream="test",
            log_lines=[f"line {i}" for i in range(200)],
        )
        prompt = build_prompt(parsed)
        # Count lines in the prompt that look like log lines
        assert f"({MAX_LINES} lines" in prompt

    def test_sns_prompt_contains_alarm_name(self):
        from src.prompts.analysis_prompt import build_prompt

        parsed = self._get_sns_parsed()
        prompt = build_prompt(parsed)
        assert "HighErrorRate" in prompt

    def test_prompt_contains_schema(self):
        from src.prompts.analysis_prompt import build_prompt

        parsed = self._get_cwl_parsed()
        prompt = build_prompt(parsed)
        assert "severity" in prompt
        assert "root_cause" in prompt
        assert "recommended_actions" in prompt

    def test_system_prompt_not_empty(self):
        from src.prompts.analysis_prompt import SYSTEM_PROMPT

        assert len(SYSTEM_PROMPT) > 50


# ---------------------------------------------------------------------------
# claude_client tests
# ---------------------------------------------------------------------------


class TestClaudeClient:
    def test_extract_json_clean(self):
        from src.utils.claude_client import _extract_json

        text = json.dumps(MOCK_ANALYSIS)
        result = _extract_json(text)
        assert result["severity"] == "HIGH"

    def test_extract_json_with_markdown_fences(self):
        from src.utils.claude_client import _extract_json

        text = f"```json\n{json.dumps(MOCK_ANALYSIS)}\n```"
        result = _extract_json(text)
        assert result["summary"] == MOCK_ANALYSIS["summary"]

    def test_extract_json_embedded(self):
        from src.utils.claude_client import _extract_json

        text = f"Here is the analysis:\n{json.dumps(MOCK_ANALYSIS)}\nEnd."
        result = _extract_json(text)
        assert result["root_cause"] == MOCK_ANALYSIS["root_cause"]

    def test_extract_json_invalid_raises(self):
        from src.utils.claude_client import _extract_json

        with pytest.raises(ValueError):
            _extract_json("not json at all")

    def test_validate_analysis_valid(self):
        from src.utils.claude_client import _validate_analysis

        result = _validate_analysis(dict(MOCK_ANALYSIS))
        assert result["severity"] == "HIGH"

    def test_validate_analysis_invalid_severity_defaults_to_high(self):
        from src.utils.claude_client import _validate_analysis

        data = dict(MOCK_ANALYSIS)
        data["severity"] = "BOGUS"
        result = _validate_analysis(data)
        assert result["severity"] == "HIGH"

    def test_validate_analysis_missing_key_raises(self):
        from src.utils.claude_client import _validate_analysis

        data = dict(MOCK_ANALYSIS)
        del data["root_cause"]
        with pytest.raises(ValueError, match="root_cause"):
            _validate_analysis(data)

    def test_validate_analysis_empty_list_gets_na(self):
        from src.utils.claude_client import _validate_analysis

        data = dict(MOCK_ANALYSIS)
        data["error_patterns"] = []
        result = _validate_analysis(data)
        assert result["error_patterns"] == ["N/A"]

    @patch("src.utils.claude_client._resolve_api_key", return_value="test-key")
    @patch("anthropic.Anthropic")
    def test_analyze_logs_success(self, mock_anthropic_cls, mock_resolve):
        import src.utils.claude_client as cc
        from src.utils.claude_client import analyze_logs

        cc._api_key_cache = None

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_message = MagicMock()
        mock_message.content = [MagicMock(text=json.dumps(MOCK_ANALYSIS))]
        mock_message.stop_reason = "end_turn"
        mock_message.usage.output_tokens = 200
        mock_client.messages.create.return_value = mock_message

        result = analyze_logs("system", "user")
        assert result["severity"] == "HIGH"
        mock_client.messages.create.assert_called_once()


# ---------------------------------------------------------------------------
# notifier tests
# ---------------------------------------------------------------------------


class TestNotifier:
    def test_telegram_message_format_critical(self):
        from src.utils.notifier import _format_telegram_message

        analysis = dict(MOCK_ANALYSIS)
        analysis["severity"] = "CRITICAL"
        msg = _format_telegram_message(analysis, "/aws/lambda/fn", "sns_alarm")
        assert "🔴" in msg
        assert "CRITICAL" in msg
        assert "Root Cause" in msg
        assert "/aws/lambda/fn" in msg

    def test_telegram_message_all_severities(self):
        from src.utils.notifier import SEVERITY_EMOJI, _format_telegram_message

        for sev, emoji in SEVERITY_EMOJI.items():
            analysis = dict(MOCK_ANALYSIS)
            analysis["severity"] = sev
            msg = _format_telegram_message(analysis, "/test", "cwl_subscription")
            assert emoji in msg

    def test_slack_blocks_structure(self):
        from src.utils.notifier import _build_slack_blocks

        blocks = _build_slack_blocks(MOCK_ANALYSIS, "/aws/lambda/fn", "sns_alarm")
        assert isinstance(blocks, list)
        assert len(blocks) == 1
        attachment = blocks[0]
        assert "color" in attachment
        assert "blocks" in attachment
        # Find header block
        header_blocks = [b for b in attachment["blocks"] if b.get("type") == "header"]
        assert len(header_blocks) == 1
        assert "HIGH" in header_blocks[0]["text"]["text"]

    def test_slack_color_by_severity(self):
        from src.utils.notifier import SEVERITY_COLOR, _build_slack_blocks

        for sev, color in SEVERITY_COLOR.items():
            analysis = dict(MOCK_ANALYSIS)
            analysis["severity"] = sev
            blocks = _build_slack_blocks(analysis, "/test", "cwl_subscription")
            assert blocks[0]["color"] == color

    @patch("src.utils.notifier._get_ssm_value", return_value="fake-token")
    @patch("src.utils.notifier._http_post")
    def test_send_telegram_success(self, mock_post, mock_ssm):
        os.environ["TELEGRAM_CHAT_ID"] = "-100123456"
        from src.utils.notifier import send_telegram

        mock_post.return_value = {"ok": True, "result": {"message_id": 1}}
        result = send_telegram(MOCK_ANALYSIS, "/test", "cwl_subscription")
        assert result is True
        mock_post.assert_called_once()

    @patch("src.utils.notifier._get_ssm_value", return_value="fake-token")
    @patch("src.utils.notifier._http_post")
    def test_send_telegram_api_error_returns_false(self, mock_post, mock_ssm):
        os.environ["TELEGRAM_CHAT_ID"] = "-100123456"
        from src.utils.notifier import send_telegram

        mock_post.return_value = {"ok": False, "description": "Forbidden"}
        result = send_telegram(MOCK_ANALYSIS, "/test", "cwl_subscription")
        assert result is False

    @patch("src.utils.notifier._get_ssm_value", return_value="https://hooks.slack.com/fake")
    @patch("src.utils.notifier._http_post")
    def test_send_slack_success(self, mock_post, mock_ssm):
        from src.utils.notifier import send_slack

        mock_post.return_value = {}
        result = send_slack(MOCK_ANALYSIS, "/test", "sns_alarm")
        assert result is True

    @patch("src.utils.notifier._get_ssm_value", side_effect=Exception("SSM error"))
    def test_send_slack_ssm_failure_returns_false(self, mock_ssm):
        from src.utils.notifier import send_slack

        result = send_slack(MOCK_ANALYSIS, "/test", "sns_alarm")
        assert result is False


# ---------------------------------------------------------------------------
# handler integration tests
# ---------------------------------------------------------------------------


class TestHandler:
    def _mock_analyze_logs(self, *args, **kwargs):
        return dict(MOCK_ANALYSIS)

    def _mock_send_notifications(self, *args, **kwargs):
        return {"telegram": True, "slack": True}

    @patch("src.handlers.log_analyzer.send_notifications")
    @patch("src.handlers.log_analyzer.analyze_logs")
    def test_handler_cwl_event(self, mock_analyze, mock_notify):
        mock_analyze.return_value = dict(MOCK_ANALYSIS)
        mock_notify.return_value = {"telegram": True, "slack": True}
        from src.handlers.log_analyzer import handler

        response = handler(_cwl_subscription_event(), None)
        assert response["statusCode"] == 200
        assert len(response["results"]) == 1
        assert response["results"][0]["source"] == "cwl_subscription"
        assert response["results"][0]["analysis"]["severity"] == "HIGH"

    @patch("src.handlers.log_analyzer.send_notifications")
    @patch("src.handlers.log_analyzer.analyze_logs")
    def test_handler_sns_event(self, mock_analyze, mock_notify):
        mock_analyze.return_value = dict(MOCK_ANALYSIS)
        mock_notify.return_value = {"telegram": True, "slack": True}
        from src.handlers.log_analyzer import handler

        response = handler(_sns_alarm_event(), None)
        assert response["statusCode"] == 200
        assert len(response["results"]) == 1
        assert response["results"][0]["source"] == "sns_alarm"

    @patch("src.handlers.log_analyzer.send_notifications")
    @patch("src.handlers.log_analyzer.analyze_logs")
    def test_handler_returns_207_on_partial_error(self, mock_analyze, mock_notify):
        mock_analyze.side_effect = RuntimeError("Claude unavailable")
        mock_notify.return_value = {"telegram": False, "slack": False}
        from src.handlers.log_analyzer import handler

        response = handler(_cwl_subscription_event(), None)
        assert response["statusCode"] == 207
        assert len(response["errors"]) == 1

    def test_handler_unknown_event_returns_empty(self):
        from src.handlers.log_analyzer import handler

        response = handler({"unknown": "event"}, None)
        assert response["statusCode"] == 200
        assert response["results"] == []

    @patch("src.handlers.log_analyzer.send_notifications")
    @patch("src.handlers.log_analyzer.analyze_logs")
    def test_handler_notification_results_in_response(self, mock_analyze, mock_notify):
        mock_analyze.return_value = dict(MOCK_ANALYSIS)
        mock_notify.return_value = {"telegram": True, "slack": False}
        from src.handlers.log_analyzer import handler

        response = handler(_cwl_subscription_event(), None)
        notifs = response["results"][0]["notifications"]
        assert notifs["telegram"] is True
        assert notifs["slack"] is False
