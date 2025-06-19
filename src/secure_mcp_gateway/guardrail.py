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
    # Anonymize PII in text (async)
    anonymized_text, key = await anonymize_pii("John's email is john@example.com")

    # Check response relevancy (async)
    relevancy_result = await check_relevancy("What is Python?", "Python is a programming language")

    # Check for hallucinations (async)
    hallucination_result = await check_hallucination("Tell me about Mars",
                                             "Mars is a red planet",
                                             context="Solar system information")
    ```
"""

import asyncio
import aiohttp
from typing import Tuple, Dict, Any

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
    sys_print(f"ENKRYPT_BASE_URL: {ENKRYPT_BASE_URL}")

# URLs
PII_REDACTION_URL = f"{ENKRYPT_BASE_URL}/guardrails/pii"
GUARDRAIL_URL = f"{ENKRYPT_BASE_URL}/guardrails/policy/detect"
RELEVANCY_URL = f"{ENKRYPT_BASE_URL}/guardrails/relevancy"
ADHERENCE_URL = f"{ENKRYPT_BASE_URL}/guardrails/adherence"
HALLUCINATION_URL = f"{ENKRYPT_BASE_URL}/guardrails/hallucination"

DEFAULT_HEADERS = {
    "Content-Type": "application/json"
}

# HTTP client configuration
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=30, connect=10)
MAX_RETRIES = 3
RETRY_DELAY = 1.0

# Global session for connection pooling
_http_session = None


async def get_http_session() -> aiohttp.ClientSession:
    """Get or create a global HTTP session for connection pooling."""
    global _http_session
    if _http_session is None or _http_session.closed:
        connector = aiohttp.TCPConnector(
            limit=100,  # Total connection pool size
            limit_per_host=30,  # Per-host connection limit
            ttl_dns_cache=300,  # DNS cache TTL
            use_dns_cache=True,
        )
        _http_session = aiohttp.ClientSession(
            connector=connector,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": f"enkrypt-mcp-gateway/{__version__}"}
        )
    return _http_session


async def close_http_session():
    """Close the global HTTP session."""
    global _http_session
    if _http_session and not _http_session.closed:
        await _http_session.close()
        _http_session = None


async def make_http_request(url: str, payload: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Make an async HTTP request with retry logic and proper error handling.
    
    Args:
        url: The URL to make the request to
        payload: The JSON payload to send
        headers: HTTP headers to include
        
    Returns:
        Dict containing the response data or error information
    """
    session = await get_http_session()
    
    for attempt in range(MAX_RETRIES):
        try:
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:  # Rate limited
                    if attempt < MAX_RETRIES - 1:
                        wait_time = RETRY_DELAY * (2 ** attempt)
                        sys_print(f"Rate limited, waiting {wait_time}s before retry {attempt + 1}")
                        await asyncio.sleep(wait_time)
                        continue
                else:
                    response.raise_for_status()
                    
        except aiohttp.ClientError as e:
            if attempt < MAX_RETRIES - 1:
                wait_time = RETRY_DELAY * (2 ** attempt)
                sys_print(f"HTTP request failed (attempt {attempt + 1}): {e}, retrying in {wait_time}s")
                await asyncio.sleep(wait_time)
                continue
            else:
                sys_print(f"HTTP request failed after {MAX_RETRIES} attempts: {e}")
                return {"error": str(e)}
        except Exception as e:
            sys_print(f"Unexpected error in HTTP request: {e}")
            return {"error": str(e)}
    
    return {"error": "Maximum retries exceeded"}


# --- PII Handling ---

async def anonymize_pii(text: str) -> Tuple[str, str]:
    """
    Anonymizes PII in the given text using EnkryptAI API (async).

    Args:
        text (str): The original text containing PII.

    Returns:
        Tuple[str, str]: A tuple of (anonymized_text, key)
    """
    payload = {
        "text": text,
        "mode": "request",
        "key": "null"
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making async request to PII redaction API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}")
        sys_print(f"headers: {headers}")

    try:
        data = await make_http_request(PII_REDACTION_URL, payload, headers)
        if "error" in data:
            sys_print(f"Anonymization error: {data['error']}")
            return "", ""
        return data.get("text", ""), data.get("key", "")
    except Exception as e:
        sys_print(f"Anonymization error: {e}")
        return "", ""


async def deanonymize_pii(text: str, key: str) -> str:
    """
    De-anonymizes previously redacted text using the key (async).

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

    sys_print("Making async request to PII redaction API for de-anonymization")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}")
        sys_print(f"headers: {headers}")

    try:
        data = await make_http_request(PII_REDACTION_URL, payload, headers)
        if "error" in data:
            sys_print(f"De-anonymization error: {data['error']}")
            return ""
        return data.get("text", "")
    except Exception as e:
        sys_print(f"De-anonymization error: {e}")
        return ""


async def check_relevancy(question: str, llm_answer: str) -> Dict[str, Any]:
    """
    Checks the relevancy of an LLM answer to a question using EnkryptAI API (async).

    Args:
        question (str): The original question or prompt.
        llm_answer (str): The LLM's answer to the question.

    Returns:
        Dict[str, Any]: The response from the relevancy API (parsed JSON).
    """
    payload = {
        "question": question,
        "llm_answer": llm_answer
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making async request to relevancy API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}")
        sys_print(f"headers: {headers}")

    try:
        data = await make_http_request(RELEVANCY_URL, payload, headers)
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"relevancy response: {data}")
        return data
    except Exception as e:
        sys_print(f"Relevancy API error: {e}")
        return {"error": str(e)}


async def check_adherence(context: str, llm_answer: str) -> Dict[str, Any]:
    """
    Checks the adherence of an LLM answer to a context using EnkryptAI API (async).

    Args:
        context (str): The original context or prompt.
        llm_answer (str): The LLM's answer to the context.

    Returns:
        Dict[str, Any]: The response from the adherence API (parsed JSON).
    """
    payload = {
        "context": context,
        "llm_answer": llm_answer
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making async request to adherence API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}")
        sys_print(f"headers: {headers}")

    try:
        data = await make_http_request(ADHERENCE_URL, payload, headers)
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"adherence response: {data}")
        return data
    except Exception as e:
        sys_print(f"Adherence API error: {e}")
        return {"error": str(e)}


async def check_hallucination(request_text: str, response_text: str, context: str = "") -> Dict[str, Any]:
    """
    Checks for hallucinations in an LLM response using EnkryptAI API (async).

    Args:
        request_text (str): The original request or prompt.
        response_text (str): The LLM's response to check.
        context (str): Additional context for the check (optional).

    Returns:
        Dict[str, Any]: The response from the hallucination API (parsed JSON).
    """
    payload = {
        "request_text": request_text,
        "response_text": response_text,
        "context": context
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print("Making async request to hallucination API")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}")
        sys_print(f"headers: {headers}")

    try:
        data = await make_http_request(HALLUCINATION_URL, payload, headers)
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"hallucination response: {data}")
        return data
    except Exception as e:
        sys_print(f"Hallucination API error: {e}")
        return {"error": str(e)}


async def call_guardrail(text: str, blocks: list, policy_name: str) -> Tuple[bool, list, Dict[str, Any]]:
    """
    Calls the guardrail API to check for policy violations (async).

    Args:
        text (str): The text to check for violations.
        blocks (list): List of policy blocks to check against.
        policy_name (str): Name of the policy being checked.

    Returns:
        Tuple[bool, list, Dict[str, Any]]: A tuple of (violations_detected, violation_types, response)
    """
    payload = {
        "text": text,
        "blocks": blocks,
        "policy_name": policy_name
    }
    headers = {**DEFAULT_HEADERS, "apikey": ENKRYPT_API_KEY}

    sys_print(f"Making async request to guardrail API for policy: {policy_name}")
    if IS_DEBUG_LOG_LEVEL:
        sys_print(f"payload: {payload}")
        sys_print(f"headers: {headers}")

    try:
        data = await make_http_request(GUARDRAIL_URL, payload, headers)
        
        if "error" in data:
            sys_print(f"Guardrail API error: {data['error']}")
            return False, [], data

        violations_detected = data.get("violations_detected", False)
        violation_types = data.get("violation_types", [])
        
        if IS_DEBUG_LOG_LEVEL:
            sys_print(f"guardrail response: {data}")
            sys_print(f"violations_detected: {violations_detected}")
            sys_print(f"violation_types: {violation_types}")

        return violations_detected, violation_types, data
        
    except Exception as e:
        sys_print(f"Guardrail API error: {e}")
        return False, [], {"error": str(e)}


# Cleanup function for graceful shutdown
async def cleanup_guardrail_module():
    """Clean up resources when shutting down."""
    await close_http_session()


# Legacy sync functions for backward compatibility (deprecated)
def anonymize_pii_sync(text: str) -> Tuple[str, str]:
    """Deprecated: Use anonymize_pii() instead."""
    import warnings
    warnings.warn("anonymize_pii_sync is deprecated, use async anonymize_pii instead", DeprecationWarning)
    return asyncio.run(anonymize_pii(text))


def deanonymize_pii_sync(text: str, key: str) -> str:
    """Deprecated: Use deanonymize_pii() instead."""
    import warnings
    warnings.warn("deanonymize_pii_sync is deprecated, use async deanonymize_pii instead", DeprecationWarning)
    return asyncio.run(deanonymize_pii(text, key))
