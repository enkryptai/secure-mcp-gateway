# FIXED VERSION - Copy this to guardrail_service.py

from typing import Any, Dict, List, Tuple

import aiohttp
import requests

from secure_mcp_gateway.utils import get_common_config, sys_print
from secure_mcp_gateway.version import __version__

# Removed circular import - will be imported when needed

# Global manager instance (set by gateway.py)
GUARDRAIL_MANAGER = None


class GuardrailService:
    """
    Guardrail service for Enkrypt Secure MCP Gateway.
    Handles all guardrail operations including PII handling, policy detection, and content quality checks.
    """

    def __init__(
        self, api_key: str = None, base_url: str = "https://api.enkryptai.com"
    ):
        """Initialize the guardrail service."""
        sys_print("Initializing Enkrypt Secure MCP Gateway Guardrail Service")
        self.api_key = api_key
        self.base_url = base_url

        # Get configuration
        self.common_config = get_common_config()
        self.log_level = self.common_config.get("enkrypt_log_level", "INFO").lower()
        self.is_debug = self.log_level == "debug"

        # API configuration
        self.api_key = self.common_config.get("enkrypt_api_key", "null")
        self.base_url = self.common_config.get(
            "enkrypt_base_url", "https://api.enkryptai.com"
        )

        # API endpoints
        self.pii_redaction_url = f"{self.base_url}/guardrails/pii"
        self.guardrail_url = f"{self.base_url}/guardrails/policy/detect"
        self.relevancy_url = f"{self.base_url}/guardrails/relevancy"
        self.adherence_url = f"{self.base_url}/guardrails/adherence"
        self.hallucination_url = f"{self.base_url}/guardrails/hallucination"

        # Default headers
        self.default_headers = {"Content-Type": "application/json"}

        sys_print(f"Guardrail service initialized with base URL: {self.base_url}")

    # ============================================================================
    # Legacy Enkrypt Methods (keep for backward compatibility)
    # ============================================================================

    def guardrail_response_has_pii_redaction(
        self, guardrail_response: Dict[str, Any]
    ) -> bool:
        """
        Check if the guardrail response already contains PII redaction information.

        Args:
            guardrail_response: The response from the guardrail API

        Returns:
            bool: True if PII redaction is already included in the response
        """
        if not guardrail_response or not isinstance(guardrail_response, dict):
            return False

        # Check if the response has PII information in the summary
        summary = guardrail_response.get("summary", {})
        if "pii" in summary and summary["pii"] > 0:
            return True

        # Check if the response has PII details
        details = guardrail_response.get("details", {})
        if "pii" in details:
            return True

        return False

    async def call_guardrail_async(
        self, text: str, blocks: List[str], policy_name: str
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Asynchronously checks text against specified guardrail policies using EnkryptAI API.

        NOTE: This is a legacy method. New code should use the plugin system.

        Args:
            text (str): The text to be checked against guardrail policies.
            blocks (list): List of policy blocks to check against.
            policy_name (str): Name of the policy to apply.

        Returns:
            tuple: (violations_detected, violation_types, resp_json)
        """
        payload = {"text": text}
        headers = {
            "X-Enkrypt-Policy": policy_name,
            "apikey": self.api_key,
            "Content-Type": "application/json",
        }

        sys_print(f"making request to guardrail with policy: {policy_name}")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)
            sys_print(f"headers: {headers}", is_debug=True)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.guardrail_url, json=payload, headers=headers
                ) as response:
                    resp_json = await response.json()
        except Exception as e:
            sys_print(f"Guardrail API error: {e}", is_error=True)
            return False, [], {"error": str(e)}

        if self.is_debug:
            sys_print("Guardrail API response received", is_debug=True)
            sys_print(f"resp_json: {resp_json}", is_debug=True)

        if resp_json.get("error"):
            sys_print(f"Guardrail API error: {resp_json.get('error')}", is_error=True)
            return False, [], resp_json

        violations_detected = False
        violation_types = []

        if "summary" in resp_json:
            summary = resp_json["summary"]
            for policy_type in blocks:
                value = summary.get(policy_type)
                if self.is_debug:
                    sys_print(f"policy_type: {policy_type}", is_debug=True)
                    sys_print(f"value: {value}", is_debug=True)

                if value == 1:
                    violations_detected = True
                    violation_types.append(policy_type)
                elif isinstance(value, list) and len(value) > 0:
                    violations_detected = True
                    violation_types.append(policy_type)

        return violations_detected, violation_types, resp_json

    def anonymize_pii(self, text: str) -> Tuple[str, str]:
        """
        Anonymizes PII in the given text using EnkryptAI API.

        Args:
            text (str): The original text containing PII.

        Returns:
            tuple[str, str]: A tuple of (anonymized_text, key)
        """
        payload = {"text": text, "mode": "request", "key": "null"}
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to PII redaction API")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)
            sys_print(f"headers: {headers}", is_debug=True)

        try:
            response = requests.post(
                self.pii_redaction_url, json=payload, headers=headers
            )
            response.raise_for_status()
            data = response.json()
            return data["text"], data["key"]
        except Exception as e:
            sys_print(f"Anonymization error: {e}", is_error=True)
            return "", ""

    def deanonymize_pii(self, text: str, key: str) -> str:
        """
        De-anonymizes previously redacted text using the key.

        Args:
            text (str): The anonymized text
            key (str): The key returned during anonymization.

        Returns:
            str: The fully de-anonymized text.
        """
        payload = {"text": text, "mode": "response", "key": key}
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to PII redaction API for de-anonymization")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)
            sys_print(f"headers: {headers}", is_debug=True)

        try:
            response = requests.post(
                self.pii_redaction_url, json=payload, headers=headers
            )
            response.raise_for_status()
            data = response.json()
            return data["text"]
        except Exception as e:
            sys_print(f"De-anonymization error: {e}", is_error=True)
            return ""

    def check_relevancy(self, question: str, llm_answer: str) -> Dict[str, Any]:
        """Checks relevancy using EnkryptAI API."""
        payload = {"question": question, "llm_answer": llm_answer}
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to relevancy API")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)

        try:
            response = requests.post(self.relevancy_url, json=payload, headers=headers)
            response.raise_for_status()
            res_json = response.json()
            if self.is_debug:
                sys_print(f"relevancy response: {res_json}", is_debug=True)
            return res_json
        except Exception as e:
            sys_print(f"Relevancy API error: {e}", is_error=True)
            return {"error": str(e)}

    def check_adherence(self, context: str, llm_answer: str) -> Dict[str, Any]:
        """Checks adherence using EnkryptAI API."""
        payload = {"context": context, "llm_answer": llm_answer}
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to adherence API")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)

        try:
            response = requests.post(self.adherence_url, json=payload, headers=headers)
            response.raise_for_status()
            res_json = response.json()
            if self.is_debug:
                sys_print(f"adherence response: {res_json}", is_debug=True)
            return res_json
        except Exception as e:
            sys_print(f"Adherence API error: {e}", is_error=True)
            return {"error": str(e)}

    def check_hallucination(
        self, request_text: str, response_text: str, context: str = ""
    ) -> Dict[str, Any]:
        """Checks hallucination using EnkryptAI API."""
        payload = {
            "request_text": request_text,
            "response_text": response_text,
            "context": context if context else "",
        }
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to hallucination API")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)

        try:
            response = requests.post(
                self.hallucination_url, json=payload, headers=headers
            )
            response.raise_for_status()
            res_json = response.json()
            if self.is_debug:
                sys_print(f"hallucination response: {res_json}", is_debug=True)
            return res_json
        except Exception as e:
            sys_print(f"Hallucination API error: {e}", is_error=True)
            return {"error": str(e)}

    # ============================================================================
    # NEW: Plugin System Methods
    # ============================================================================

    async def check_input_guardrails(
        self, server_config: Dict[str, Any], tool_name: str, tool_args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check input guardrails using the plugin system.

        Args:
            server_config: Server configuration dict
            tool_name: Name of the tool being called
            tool_args: Tool arguments

        Returns:
            dict: Guardrail check results
        """
        global GUARDRAIL_MANAGER

        if GUARDRAIL_MANAGER is None:
            from secure_mcp_gateway.plugins.guardrails import (
                get_guardrail_config_manager,
            )

            GUARDRAIL_MANAGER = get_guardrail_config_manager()

        # Get the appropriate guardrail for this server
        input_guardrail = GUARDRAIL_MANAGER.get_input_guardrail(server_config)

        if input_guardrail is None:
            # Guardrails not enabled for this server
            return {
                "status": "success",
                "is_safe": True,
                "message": "No input guardrails configured",
            }

        # Create request
        from secure_mcp_gateway.plugins.guardrails import GuardrailRequest

        request = GuardrailRequest(
            content=str(tool_args),
            tool_name=tool_name,
            tool_args=tool_args,
            server_name=server_config.get("server_name"),
            context={
                "environment": "production",
            },
        )

        # Validate
        try:
            response = await input_guardrail.validate(request)

            if response.is_safe:
                return {
                    "status": "success",
                    "is_safe": True,
                    "message": "Input validation passed",
                    "metadata": response.metadata,
                }
            else:
                return {
                    "status": "blocked",
                    "is_safe": False,
                    "message": "Input validation failed",
                    "violations": [
                        {
                            "type": v.violation_type.value,
                            "severity": v.severity,
                            "message": v.message,
                            "action": v.action.value,
                        }
                        for v in response.violations
                    ],
                    "metadata": response.metadata,
                }

        except Exception as e:
            sys_print(f"Error in guardrail check: {e}", is_error=True)

            # Decide whether to fail open or closed based on config
            fail_open = server_config.get("input_guardrails_policy", {}).get(
                "fail_open", False
            )

            return {
                "status": "error" if not fail_open else "success",
                "is_safe": fail_open,
                "message": f"Guardrail error: {e!s}",
                "error": str(e),
            }

    async def check_output_guardrails(
        self,
        server_config: Dict[str, Any],
        response_content: str,
        original_request: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Check output guardrails using the plugin system.

        Args:
            server_config: Server configuration dict
            response_content: Response content from the tool
            original_request: Original request that triggered the tool call

        Returns:
            dict: Guardrail check results
        """
        global GUARDRAIL_MANAGER

        if GUARDRAIL_MANAGER is None:
            from secure_mcp_gateway.plugins.guardrails import (
                get_guardrail_config_manager,
            )

            GUARDRAIL_MANAGER = get_guardrail_config_manager()

        output_guardrail = GUARDRAIL_MANAGER.get_output_guardrail(server_config)

        if output_guardrail is None:
            return {
                "status": "success",
                "is_safe": True,
                "message": "No output guardrails configured",
            }

        try:
            from secure_mcp_gateway.plugins.guardrails import GuardrailRequest

            response = await output_guardrail.validate(
                response_content,
                GuardrailRequest(
                    content=original_request.get("content", ""),
                    tool_name=original_request.get("tool_name"),
                    tool_args=original_request.get("tool_args"),
                ),
            )

            if response.is_safe:
                return {
                    "status": "success",
                    "is_safe": True,
                    "modified_content": response.modified_content,
                    "metadata": response.metadata,
                }
            else:
                return {
                    "status": "blocked",
                    "is_safe": False,
                    "violations": [
                        {
                            "type": v.violation_type.value,
                            "severity": v.severity,
                            "message": v.message,
                        }
                        for v in response.violations
                    ],
                    "metadata": response.metadata,
                }

        except Exception as e:
            sys_print(f"Error in output guardrail check: {e}", is_error=True)
            fail_open = server_config.get("output_guardrails_policy", {}).get(
                "fail_open", False
            )

            return {
                "status": "error" if not fail_open else "success",
                "is_safe": fail_open,
                "message": f"Guardrail error: {e!s}",
                "error": str(e),
            }


# Global guardrail service instance
guardrail_service = GuardrailService()
