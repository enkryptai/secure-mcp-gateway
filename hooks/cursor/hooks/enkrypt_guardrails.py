#!/usr/bin/env python
"""
Enkrypt AI Guardrails - Shared Module

This module provides the core Enkrypt API integration used by all hooks:
- beforeSubmitPrompt (input guardrails)
- beforeMCPExecution (input guardrails)
- afterMCPExecution (output guardrails)
- afterAgentResponse (output guardrails)
- stop

Configuration is loaded from guardrails_config.json
"""
# Suppress requests library warnings (urllib3/chardet version mismatches)
import warnings
warnings.filterwarnings("ignore", message="urllib3.*or chardet.*doesn't match")
warnings.filterwarnings("ignore", category=DeprecationWarning)

import os
import json
import datetime
from pathlib import Path

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

CONFIG_FILE = Path(__file__).parent / "guardrails_config.json"
LOG_DIR = Path(os.environ.get("CURSOR_HOOKS_LOG_DIR", Path.home() / "cursor" / "hooks_logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    """Load configuration from guardrails_config.json"""
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log_event("config_error", {"error": str(e), "config_file": str(CONFIG_FILE)})
        return {}


# Load config on module import
CONFIG = load_config()

# Extract configuration values (strip whitespace to avoid URL issues)
ENKRYPT_API_URL = os.environ.get(
    "ENKRYPT_API_URL",
    CONFIG.get("enkrypt_api", {}).get("url", "https://api.enkryptai.com/guardrails/policy/detect")
).strip()
ENKRYPT_API_KEY = os.environ.get(
    "ENKRYPT_API_KEY",
    CONFIG.get("enkrypt_api", {}).get("api_key", "")
).strip()

SENSITIVE_MCP_TOOLS = CONFIG.get("sensitive_mcp_tools", [])

# Hook-specific policies
HOOK_POLICIES = {
    "beforeSubmitPrompt": CONFIG.get("beforeSubmitPrompt", {}),
    "beforeMCPExecution": CONFIG.get("beforeMCPExecution", {}),
    "afterMCPExecution": CONFIG.get("afterMCPExecution", {}),
    "afterAgentResponse": CONFIG.get("afterAgentResponse", {}),
}


# ============================================================================
# POLICY FUNCTIONS
# ============================================================================

def get_hook_policy(hook_name: str) -> dict:
    """Get policy config for a specific hook."""
    return HOOK_POLICIES.get(hook_name, {})


def is_hook_enabled(hook_name: str) -> bool:
    """Check if guardrails are enabled for a specific hook."""
    return get_hook_policy(hook_name).get("enabled", False)


def get_hook_block_list(hook_name: str) -> list:
    """Get list of detectors that should block for a specific hook."""
    return get_hook_policy(hook_name).get("block", [])


def get_hook_policy_name(hook_name: str) -> str:
    """Get policy name for a specific hook."""
    return get_hook_policy(hook_name).get("policy_name", f"Default {hook_name} Policy")


# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def get_timestamp():
    """Get ISO format timestamp."""
    return datetime.datetime.now().isoformat()


def log_event(hook_name: str, data: dict, result: dict = None):
    """Log a hook event to a JSON Lines file."""
    log_file = LOG_DIR / f"{hook_name}.jsonl"

    entry = {
        "timestamp": get_timestamp(),
        "hook": hook_name,
        "input": data,
    }
    if result is not None:
        entry["output"] = result

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def log_to_combined(hook_name: str, data: dict, result: dict = None):
    """Log to a combined audit log file."""
    log_file = LOG_DIR / "combined_audit.jsonl"

    entry = {
        "timestamp": get_timestamp(),
        "hook": hook_name,
        "conversation_id": data.get("conversation_id"),
        "generation_id": data.get("generation_id"),
        "model": data.get("model"),
        "user_email": data.get("user_email"),
        "data": data,
    }
    if result is not None:
        entry["result"] = result

    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def log_security_alert(alert_type: str, details: dict, data: dict):
    """Log a security alert."""
    alert_file = LOG_DIR / "security_alerts.jsonl"
    alert = {
        "timestamp": get_timestamp(),
        "type": alert_type,
        **details,
        "conversation_id": data.get("conversation_id"),
        "user_email": data.get("user_email"),
    }
    with open(alert_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert) + "\n")


# ============================================================================
# ENKRYPT API RESPONSE PARSING
# ============================================================================

def parse_enkrypt_response(result: dict, block_list: list) -> list:
    """
    Parse Enkrypt API response and extract violations.

    API Response Format:
    {
      "summary": {
        "on_topic": 0,
        "nsfw": 1,
        "toxicity": ["toxicity", "insult"],
        "pii": 1,
        "injection_attack": 1,
        "keyword_detected": 1,
        "policy_violation": 1,
        "bias": 1,
        "sponge_attack": 1
      },
      "details": {
        "topic_detector": {...},
        "nsfw": {...},
        "toxicity": {...},
        "pii": {...},
        "injection_attack": {...},
        "keyword_detector": {...},
        "policy_violation": {...},
        "bias": {...},
        "sponge_attack": {...}
      }
    }
    """
    violations = []
    summary = result.get("summary", {})
    details = result.get("details", {})

    # Map summary keys to detector names in block list
    detector_mapping = {
        "nsfw": "nsfw",
        "toxicity": "toxicity",
        "pii": "pii",
        "injection_attack": "injection_attack",
        "keyword_detected": "keyword_detector",
        "policy_violation": "policy_violation",
        "bias": "bias",
        "sponge_attack": "sponge_attack",
        "on_topic": "topic_detector",
    }

    for summary_key, detector_name in detector_mapping.items():
        summary_value = summary.get(summary_key)

        # Check if this detector triggered
        is_detected = False
        if isinstance(summary_value, int) and summary_value == 1:
            is_detected = True
        elif isinstance(summary_value, list) and len(summary_value) > 0:
            is_detected = True
        elif isinstance(summary_value, bool) and summary_value:
            is_detected = True

        # Special case: on_topic=0 means OFF topic (potential issue), on_topic=1 means ON topic (ok)
        if summary_key == "on_topic":
            is_detected = summary_value == 0 if isinstance(summary_value, int) else False

        if is_detected and detector_name in block_list:
            violation_info = {
                "detector": detector_name,
                "detected": True,
                "blocked": True,
            }

            # Add details based on detector type
            detail = details.get(detector_name, {}) or details.get(summary_key, {})

            if detector_name == "pii":
                pii_detail = detail.get("pii", {})
                if pii_detail:
                    violation_info["entities"] = list(pii_detail.keys())
                    violation_info["pii_found"] = pii_detail

            elif detector_name == "toxicity":
                if isinstance(summary_value, list):
                    violation_info["toxicity_types"] = summary_value
                # Get toxicity score
                if "toxicity" in detail:
                    violation_info["score"] = detail.get("toxicity")

            elif detector_name == "keyword_detector":
                violation_info["matched_keywords"] = detail.get("detected_keywords", [])
                violation_info["keyword_counts"] = detail.get("detected_counts", {})

            elif detector_name == "policy_violation":
                violation_info["violating_policy"] = detail.get("violating_policy", "")
                violation_info["explanation"] = detail.get("explanation", "")

            elif detector_name == "injection_attack":
                violation_info["attack_score"] = detail.get("attack", 0)

            elif detector_name == "nsfw":
                violation_info["nsfw_score"] = detail.get("nsfw", 0)

            elif detector_name == "bias":
                violation_info["bias_detected"] = detail.get("bias_detected", False)
                violation_info["debiased_text"] = detail.get("debiased_text", "")

            elif detector_name == "sponge_attack":
                violation_info["sponge_detected"] = detail.get("sponge_attack_detected", False)

            violations.append(violation_info)

    return violations


# ============================================================================
# ENKRYPT API FUNCTIONS
# ============================================================================

def check_with_enkrypt_api(text: str, hook_name: str = "beforeSubmitPrompt") -> tuple[bool, list, dict]:
    """
    Check text using Enkrypt AI Guardrails API.

    Args:
        text: The text to check (prompt or MCP input/output)
        hook_name: The hook name (beforeSubmitPrompt, beforeMCPExecution, afterMCPExecution, afterAgentResponse)

    Returns:
        Tuple of (should_block, violations_list, full_result)
    """
    # Check if guardrails are enabled for this hook
    if not is_hook_enabled(hook_name):
        return False, [], {"skipped": f"{hook_name} guardrails disabled"}

    # Get the block list for this hook
    block_list = get_hook_block_list(hook_name)

    try:
        import requests

        # Get policy name for this hook
        policy_name = get_hook_policy_name(hook_name)

        payload = {
            "text": text
        }

        # Debug: Log the actual request being made
        log_event("enkrypt_api_debug", {
            "url": ENKRYPT_API_URL,
            "api_key_length": len(ENKRYPT_API_KEY) if ENKRYPT_API_KEY else 0,
            "payload_text_length": len(text),
            "policy_name": policy_name,
            "config_file": str(CONFIG_FILE),
        })

        # Disable SSL warnings and verify for debugging
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        resp = requests.post(
            ENKRYPT_API_URL,
            headers={
                "Content-Type": "application/json",
                "apikey": ENKRYPT_API_KEY,
                "X-Enkrypt-Policy": policy_name
            },
            json=payload,
            timeout=15,
            verify=False,  # Bypass SSL verification for debugging
        )

        # Log response status before raising
        log_event("enkrypt_api_response", {
            "status_code": resp.status_code,
            "url": resp.url,
            "response_preview": resp.text[:300] if resp.text else None,
            "request_url": ENKRYPT_API_URL,
            "headers_sent": dict(resp.request.headers) if resp.request else None,
        })

        resp.raise_for_status()
        result = resp.json()

        # Parse the response using the actual API format
        violations = parse_enkrypt_response(result, block_list)

        should_block = len(violations) > 0
        return should_block, violations, result

    except ImportError:
        log_event("enkrypt_api_error", {"error": "requests library not installed"})
        return False, [], {"error": "requests not installed"}
    except Exception as e:
        error_info = {
            "error": str(e),
            "error_type": type(e).__name__,
            "url_used": ENKRYPT_API_URL,
        }
        # Try to get response details if it's an HTTP error
        if hasattr(e, 'response') and e.response is not None:
            error_info["status_code"] = e.response.status_code
            error_info["response_text"] = e.response.text[:500] if e.response.text else None
        log_event("enkrypt_api_error", error_info)
        return False, [], {"error": str(e)}


def format_violation_message(violations: list, hook_name: str = "beforeSubmitPrompt") -> str:
    """Format a user-friendly message from violations."""
    if not violations:
        return ""

    policy_name = get_hook_policy_name(hook_name)

    messages = [f"Policy: {policy_name}\n"]

    for v in violations:
        detector = v["detector"]

        if detector == "pii":
            entities = v.get("entities", [])
            pii_found = v.get("pii_found", {})
            if pii_found:
                # Show actual PII types found
                pii_items = [f"{k}" for k in list(pii_found.keys())[:3]]
                messages.append(f"🔐 PII/Secrets detected: {', '.join(pii_items)}")
            elif entities:
                messages.append(f"🔐 PII/Secrets detected: {', '.join(str(e) for e in entities[:5])}")
            else:
                messages.append("🔐 PII/Secrets detected")

        elif detector == "injection_attack":
            attack_score = v.get("attack_score", 0)
            try:
                score_float = float(attack_score) if attack_score else 0
                if score_float:
                    messages.append(f"⚠️ Injection attack detected (confidence: {score_float:.1%})")
                else:
                    messages.append("⚠️ Injection attack pattern detected")
            except (ValueError, TypeError):
                messages.append("⚠️ Injection attack pattern detected")

        elif detector == "toxicity":
            toxicity_types = v.get("toxicity_types", [])
            score = v.get("score", "N/A")
            if toxicity_types:
                messages.append(f"🚫 Toxic content detected: {', '.join(toxicity_types)} (score: {score})")
            else:
                messages.append(f"🚫 Toxic content detected (score: {score})")

        elif detector == "nsfw":
            nsfw_score = v.get("nsfw_score", 0)
            try:
                score_float = float(nsfw_score) if nsfw_score else 0
                if score_float:
                    messages.append(f"🔞 NSFW content detected (confidence: {score_float:.1%})")
                else:
                    messages.append("🔞 NSFW content detected")
            except (ValueError, TypeError):
                messages.append("🔞 NSFW content detected")

        elif detector == "keyword_detector":
            keywords = v.get("matched_keywords", [])
            if keywords:
                messages.append(f"🚫 Banned keywords detected: {', '.join(keywords)}")
            else:
                messages.append("🚫 Banned keywords detected")

        elif detector == "policy_violation":
            violating_policy = v.get("violating_policy", "")
            explanation = v.get("explanation", "")
            if violating_policy:
                messages.append(f"📋 Policy violation: {violating_policy}")
            if explanation:
                messages.append(f"   → {explanation[:150]}")

        elif detector == "bias":
            messages.append("⚖️ Bias detected in content")

        elif detector == "sponge_attack":
            messages.append("🧽 Sponge attack detected")

        elif detector == "topic_detector":
            messages.append("📌 Off-topic or sensitive topic detected")

        else:
            messages.append(f"⚠️ {detector.replace('_', ' ').title()} detected")

    return "\n".join(messages)


# ============================================================================
# MCP TOOL CHECKING
# ============================================================================

def check_mcp_tool(tool_name: str, tool_input: str) -> tuple[str, str, str]:
    """
    Check if an MCP tool should be allowed, blocked, or require confirmation.

    Returns:
        Tuple of (permission, user_message, agent_message)
    """
    tool_name_lower = tool_name.lower()

    # Check sensitive tools from config
    for sensitive in SENSITIVE_MCP_TOOLS:
        if sensitive.lower() in tool_name_lower:
            return (
                "ask",
                f"⚠️ MCP tool '{tool_name}' requires confirmation",
                f"The MCP tool '{tool_name}' requires user approval before execution."
            )

    # Try to parse tool input and check for sensitive operations
    try:
        params = json.loads(tool_input) if tool_input else {}

        # Check for SQL operations
        if "query" in params or "sql" in params:
            query = params.get("query", "") or params.get("sql", "")
            query_upper = query.upper()

            dangerous_sql = ["DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT"]
            for keyword in dangerous_sql:
                if keyword in query_upper:
                    return (
                        "ask",
                        f"⚠️ SQL operation '{keyword}' requires confirmation",
                        f"This SQL operation modifies data and requires user approval."
                    )
    except (json.JSONDecodeError, TypeError):
        pass

    # Allow by default
    return "allow", "", ""


def analyze_mcp_result(tool_name: str, result_json: str) -> dict:
    """Analyze MCP tool result for potential issues."""
    import re

    analysis = {
        "sensitive_data_hints": [],
        "result_size": len(result_json),
        "is_error": False,
    }

    result_lower = result_json.lower()

    # Patterns to detect in MCP results
    sensitive_patterns = [
        (r"password", "password reference"),
        (r"api[_-]?key", "API key reference"),
        (r"secret", "secret reference"),
        (r"token", "token reference"),
        (r"credential", "credential reference"),
    ]

    for pattern, name in sensitive_patterns:
        if re.search(pattern, result_lower):
            analysis["sensitive_data_hints"].append(name)

    # Try to detect errors in result
    try:
        result = json.loads(result_json)
        if isinstance(result, dict):
            if result.get("error") or result.get("Error"):
                analysis["is_error"] = True
            if result.get("status") in ["error", "failed", "failure"]:
                analysis["is_error"] = True
    except (json.JSONDecodeError, TypeError):
        pass

    return analysis


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def reload_config():
    """Reload configuration from file (useful for dynamic updates)."""
    global CONFIG, HOOK_POLICIES, SENSITIVE_MCP_TOOLS
    CONFIG = load_config()
    HOOK_POLICIES = {
        "beforeSubmitPrompt": CONFIG.get("beforeSubmitPrompt", {}),
        "beforeMCPExecution": CONFIG.get("beforeMCPExecution", {}),
        "afterMCPExecution": CONFIG.get("afterMCPExecution", {}),
        "afterAgentResponse": CONFIG.get("afterAgentResponse", {}),
    }
    SENSITIVE_MCP_TOOLS = CONFIG.get("sensitive_mcp_tools", [])
