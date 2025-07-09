"""
Enkrypt Secure MCP Gateway Guardrail Module

This module provides comprehensive guardrail functionality for the Enkrypt Secure MCP Gateway, including:

1. PII (Personally Identifiable Information) Handling:
   - Anonymization of sensitive data in requests
   - De-anonymization of responses
   - Secure handling of PII data using encryption keys

2. Guardrail Policy Detection:
   - Policy-based content filtering
   - Violation detection and reporting
   - Custom policy enforcement

3. Content Quality Checks:
   - Relevancy assessment of LLM responses
   - Adherence verification to context
   - Hallucination detection in responses

The module integrates with EnkryptAI's API server to provide these security and quality control features.
It uses configuration variables for configuration and API authentication.

Configuration Variables:
    enkrypt_api_key: API key for EnkryptAI API Authentication server
    enkrypt_base_url: Base URL for EnkryptAI API endpoints

API Endpoints:
    - PII Redaction: /guardrails/pii
    - Policy Detection: /guardrails/policy/detect
    - Relevancy Check: /guardrails/relevancy
    - Adherence Check: /guardrails/adherence
    - Hallucination Check: /guardrails/hallucination

Example Usage:
    ```python
    # Anonymize PII in text
    anonymized_text, key = anonymize_pii("John's email is john@example.com")

    # Check response relevancy
    relevancy_result = check_relevancy("What is Python?", "Python is a programming language")

    # Check for hallucinations
    hallucination_result = check_hallucination("Tell me about Mars",
                                             "Mars is a red planet",
                                             context="Solar system information")
    ```
"""

# import sys
import aiohttp
import requests

from secure_mcp_gateway.utils import (
    get_common_config,
    sys_print
)
from secure_mcp_gateway.version import __version__

sys_print(f"Initializing Enkrypt Secure MCP Gateway Guardrail Module v{__version__}")

common_config = get_common_config()

ENKRYPT_LOG_LEVEL = common_config.get("enkrypt_log_level", "INFO").lower()
IS_DEBUG_LOG_LEVEL = ENKRYPT_LOG_LEVEL == "debug"

# API Key
ENKRYPT_API_KEY = common_config.get("enkrypt_api_key", "null")

ENKRYPT_BASE_URL = common_config.get("enkrypt_base_url", "https://api.enkryptai.com")
if IS_DEBUG_LOG_LEVEL:
    sys_print(f"ENKRYPT_BASE_URL: {ENKRYPT_BASE_URL}", is_debug=True)


# URLs
PII_REDACTION_URL = f"{ENKRYPT_BASE_URL}/guardrails/pii"
GUARDRAIL_URL = f"{ENKRYPT_BASE_URL}/guardrails/policy/detect"
RELEVANCY_URL = f"{ENKRYPT_BASE_URL}/guardrails/relevancy"
ADHERENCE_URL = f"{ENKRYPT_BASE_URL}/guardrails/adherence"
HALLUCINATION_URL = f"{ENKRYPT_BASE_URL}/guardrails/hallucination"

DEFAULT_HEADERS = {
    "Content-Type": "application/json"
}


# --- PII Handling ---

def anonymize_pii(text: str) -> tuple[str, str]:
    """
    Anonymizes PII in the given text using EnkryptAI API.

    Args:
        text (str): The original text containing PII.

    Returns:
        tuple[str, str]: A tuple of (anonymized_text, key)
    """
    payload = {
        "text": text,
        "mode": "request",
        "key": "null"
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making request to PII redaction API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}", is_debug=True)
        sys_print(f"headers: {headers}", is_debug=True)

    try:
        response = requests.post(PII_REDACTION_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data["text"], data["key"]
    except Exception as e:
        sys_print(f"Anonymization error: {e}", is_error=True)
        return "", ""


def deanonymize_pii(text: str, key: str) -> str:
    """
    De-anonymizes previously redacted text using the key.

    Args:
        text (str): The anonymized text (e.g., with <PERSON_0> etc.)
        key (str): The key returned during anonymization.

    Returns:
        str: The fully de-anonymized text.
    """
    payload = {
        "text": text,
        "mode": "response",
        "key": key
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making request to PII redaction API for de-anonymization")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}", is_debug=True)
        sys_print(f"headers: {headers}", is_debug=True)

    try:
        response = requests.post(PII_REDACTION_URL, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data["text"]
    except Exception as e:
        sys_print(f"De-anonymization error: {e}", is_error=True)
        return ""


def check_relevancy(question: str, llm_answer: str) -> dict:
    """
    Checks the relevancy of an LLM answer to a question using EnkryptAI API.

    Args:
        question (str): The original question or prompt.
        llm_answer (str): The LLM's answer to the question.

    Returns:
        dict: The response from the relevancy API (parsed JSON).
    """
    payload = {
        "question": question,
        "llm_answer": llm_answer
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making request to relevancy API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}", is_debug=True)
        sys_print(f"headers: {headers}", is_debug=True)

    try:
        response = requests.post(RELEVANCY_URL, json=payload, headers=headers)
        response.raise_for_status()
        res_json = response.json()
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"relevancy response: {res_json}", is_debug=True)
        return res_json
    except Exception as e:
        sys_print(f"Relevancy API error: {e}", is_error=True)
        return {"error": str(e)}


def check_adherence(context: str, llm_answer: str) -> dict:
    """
    Checks the adherence of an LLM answer to a context using EnkryptAI API.

    Args:
        context (str): The original context or prompt.
        llm_answer (str): The LLM's answer to the context.

    Returns:
        dict: The response from the adherence API (parsed JSON).
    """
    payload = {
        "context": context,
        "llm_answer": llm_answer
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making request to adherence API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}", is_debug=True)
        sys_print(f"headers: {headers}", is_debug=True)

    try:
        response = requests.post(ADHERENCE_URL, json=payload, headers=headers)
        response.raise_for_status()
        res_json = response.json()
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"adherence response: {res_json}", is_debug=True)
        return res_json
    except Exception as e:
        sys_print(f"Adherence API error: {e}", is_error=True)
        return {"error": str(e)}


def check_hallucination(request_text: str, response_text: str, context: str = "") -> dict:
    """
    Checks the hallucination of an LLM answer to a request using EnkryptAI API.

    Args:
        request_text (str): The prompt that was used to generate the response.
        response_text (str): The response from the LLM.
        context (str): The context of the request (optional).

    Returns:
        dict: The response from the hallucination API (parsed JSON).
    """
    payload = {
        "request_text": request_text,
        "response_text": response_text,
        "context": context if context else ""
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making request to hallucination API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}", is_debug=True)
        sys_print(f"headers: {headers}", is_debug=True)

    try:
        response = requests.post(HALLUCINATION_URL, json=payload, headers=headers)
        response.raise_for_status()
        res_json = response.json()
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"hallucination response: {res_json}", is_debug=True)
        return res_json
    except Exception as e:
        sys_print(f"Hallucination API error: {e}", is_error=True)
        return {"error": str(e)}


# --- Guardrail handling ---
async def call_guardrail(text, blocks, policy_name):
    """
    Asynchronously checks text against specified guardrail policies using EnkryptAI API.

    This function evaluates the input text against a set of guardrail policies to detect
    potential violations or policy breaches. It can check for multiple types of violations
    specified in the blocks parameter.

    Args:
        text (str): The text to be checked against guardrail policies.
        blocks (list): List of policy blocks to check against (e.g., ['toxicity', 'bias', 'harm']).
        policy_name (str): Name of the policy to apply (e.g., 'default', 'strict', 'custom').

    Returns:
        tuple: A tuple containing:
            - violations_detected (bool): True if any policy violations were detected, False otherwise.
            - violation_types (list): List of types of violations detected (e.g., ['toxicity', 'bias']).
            - resp_json (dict): Full response from the guardrail API including detailed analysis.

    Example:
        ```python
        violations, types, response = await call_guardrail(
            "Some text to check",
            ["toxicity", "bias"],
            "default"
        )
        if violations:
            sys_print(f"Detected violations: {types}")
        ```
    """
    payload = {"text": text}
    headers = {
        "X-Enkrypt-Policy": policy_name,
        "apikey": ENKRYPT_API_KEY,
        "Content-Type": "application/json"
    }

    sys_print(f'making request to guardrail with policy: {policy_name}')
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f'payload: {payload}', is_debug=True)
        sys_print(f'headers: {headers}', is_debug=True)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(GUARDRAIL_URL, json=payload, headers=headers) as response:
                resp_json = await response.json()
    except Exception as e:
        sys_print(f"Guardrail API error: {e}", is_error=True)
        return {"error": str(e)}

    if IS_DEBUG_LOG_LEVEL:
        sys_print("Guardrail API response received", is_debug=True)
        sys_print(f'resp_json: {resp_json}', is_debug=True)
    
    if resp_json.get("error"):
        sys_print(f"Guardrail API error: {resp_json.get('error')}", is_error=True)
        return False, [], resp_json

    violations_detected = False
    violation_types = []
    if "summary" in resp_json:
        summary = resp_json["summary"]
        for policy_type in blocks:
            value = summary.get(policy_type)
            if IS_DEBUG_LOG_LEVEL:
                sys_print(f'policy_type: {policy_type}', is_debug=True)
                sys_print(f'value: {value}', is_debug=True)
            if value == 1:
                violations_detected = True
                violation_types.append(policy_type)
            elif isinstance(value, list) and len(value) > 0:
                violations_detected = True
                violation_types.append(policy_type)

    return violations_detected, violation_types, resp_json

