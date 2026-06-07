"""
Gemini API client with SSM secret resolution.
Env var GEMINI_API_KEY_SSM_PATH holds the SSM parameter path; the raw key is never stored in env.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import boto3

logger = logging.getLogger(__name__)

MODEL_ID = "gemini-2.0-flash"
MAX_TOKENS = 1024
SSM_PATH_ENV = "GEMINI_API_KEY_SSM_PATH"
_api_key_cache: str | None = None


def _resolve_api_key() -> str:
    global _api_key_cache
    if _api_key_cache:
        return _api_key_cache

    ssm_path = os.environ.get(SSM_PATH_ENV)
    if not ssm_path:
        raise OSError(f"Environment variable {SSM_PATH_ENV} is not set")

    ssm = boto3.client("ssm", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
    response = ssm.get_parameter(Name=ssm_path, WithDecryption=True)
    _api_key_cache = response["Parameter"]["Value"]
    logger.info("Resolved Gemini API key from SSM path: %s", ssm_path)
    return _api_key_cache


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    # Strip markdown code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON object within the text
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            return json.loads(match.group())
        raise ValueError(f"No valid JSON found in Gemini response: {text[:200]}") from None


def _validate_analysis(data: dict[str, Any]) -> dict[str, Any]:
    required_keys = {
        "summary",
        "root_cause",
        "severity",
        "affected_components",
        "recommended_actions",
        "error_patterns",
        "anomalies",
    }
    missing = required_keys - set(data.keys())
    if missing:
        raise ValueError(f"Gemini response missing required keys: {missing}")

    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if data["severity"] not in valid_severities:
        logger.warning("Invalid severity '%s', defaulting to HIGH", data["severity"])
        data["severity"] = "HIGH"

    for key in ("affected_components", "recommended_actions", "error_patterns", "anomalies"):
        if not isinstance(data[key], list):
            data[key] = [str(data[key])]
        if not data[key]:
            data[key] = ["N/A"]

    return data


def analyze_logs(system_prompt: str, user_prompt: str) -> dict[str, Any]:
    import google.generativeai as genai  # lazy import — not in requirements-dev.txt

    api_key = _resolve_api_key()
    genai.configure(api_key=api_key)

    logger.info("Sending log analysis request to Gemini (%s)", MODEL_ID)
    model = genai.GenerativeModel(
        model_name=MODEL_ID,
        system_instruction=system_prompt,
        generation_config=genai.GenerationConfig(max_output_tokens=MAX_TOKENS),
    )
    response = model.generate_content(user_prompt)
    raw_text = response.text

    logger.info("Gemini response received, length=%d chars", len(raw_text))

    data = _extract_json(raw_text)
    return _validate_analysis(data)
