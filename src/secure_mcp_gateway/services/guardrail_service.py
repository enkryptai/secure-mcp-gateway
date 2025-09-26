from typing import Any, Dict, List, Tuple

import aiohttp
import requests

from secure_mcp_gateway.utils import get_common_config, sys_print
from secure_mcp_gateway.version import __version__


class GuardrailService:
    """
    Guardrail service for Enkrypt Secure MCP Gateway.
    Handles all guardrail operations including PII handling, policy detection, and content quality checks.
    """

    def __init__(self):
        """Initialize the guardrail service."""
        sys_print("Initializing Enkrypt Secure MCP Gateway Guardrail Service")

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

        Args:
            text (str): The text to be checked against guardrail policies.
            blocks (list): List of policy blocks to check against (e.g., ['toxicity', 'bias', 'harm']).
            policy_name (str): Name of the policy to apply (e.g., 'default', 'strict', 'custom').

        Returns:
            tuple: A tuple containing:
                - violations_detected (bool): True if any policy violations were detected
                - violation_types (list): List of types of violations detected
                - resp_json (dict): Full response from the guardrail API
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
            text (str): The anonymized text (e.g., with <PERSON_0> etc.)
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
        """
        Checks the relevancy of an LLM answer to a question using EnkryptAI API.

        Args:
            question (str): The original question or prompt.
            llm_answer (str): The LLM's answer to the question.

        Returns:
            dict: The response from the relevancy API (parsed JSON).
        """
        payload = {"question": question, "llm_answer": llm_answer}
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to relevancy API")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)
            sys_print(f"headers: {headers}", is_debug=True)

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
        """
        Checks the adherence of an LLM answer to a context using EnkryptAI API.

        Args:
            context (str): The original context or prompt.
            llm_answer (str): The LLM's answer to the context.

        Returns:
            dict: The response from the adherence API (parsed JSON).
        """
        payload = {"context": context, "llm_answer": llm_answer}
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to adherence API")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)
            sys_print(f"headers: {headers}", is_debug=True)

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
            "context": context if context else "",
        }
        headers = {**self.default_headers, "apikey": self.api_key}

        sys_print("Making request to hallucination API")
        if self.is_debug:
            sys_print(f"payload: {payload}", is_debug=True)
            sys_print(f"headers: {headers}", is_debug=True)

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


# Global guardrail service instance
guardrail_service = GuardrailService()
