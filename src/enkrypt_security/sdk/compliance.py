"""Compliance mapping — maps guardrail detectors to regulatory frameworks.

Ported from Sentry's ``compliance_mapping.json``.  Embeds the data directly
so no external files are needed at runtime.
"""

from __future__ import annotations

from typing import Any

COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    "injection_attack": {
        "owasp_llm_2025": ["LLM01:2025 Prompt Injection"],
        "mitre_atlas": ["AML.T0051: LLM Prompt Injection", "AML.T0054: LLM Jailbreaking"],
        "nist_ai_rmf": ["MAP 2.3, MEASURE 2.3 (Input manipulation & adversarial attacks)"],
        "eu_ai_act": ["Article 15(4) (Robustness against manipulation)"],
    },
    "pii": {
        "owasp_llm_2025": ["LLM02:2025 Sensitive Information Disclosure"],
        "nist_ai_rmf": ["MAP 1.6, GOVERN 1.6 (Privacy protection & data governance)"],
        "eu_ai_act": ["Article 10(5) (Data governance & personal data protection)"],
    },
    "toxicity": {
        "owasp_llm_2025": ["LLM09:2025 Misinformation", "LLM05:2025 Improper Output Handling"],
        "mitre_atlas": ["AML.T0056: LLM Meta Prompt Extraction"],
        "nist_ai_rmf": ["MANAGE 2.3, MEASURE 2.7 (Harmful bias & toxicity management)"],
        "eu_ai_act": ["Article 15(1) (Accuracy, robustness & safety)"],
    },
    "nsfw": {
        "owasp_llm_2025": ["LLM05:2025 Improper Output Handling"],
        "nist_ai_rmf": ["MANAGE 2.3 (Content filtering & harmful output prevention)"],
        "eu_ai_act": ["Article 50(2) (Restrictions on prohibited practices)"],
    },
    "bias": {
        "owasp_llm_2025": ["LLM09:2025 Misinformation", "LLM04:2025 Data and Model Poisoning"],
        "nist_ai_rmf": ["MEASURE 2.1-2.5 (AI system bias evaluation & management)"],
        "eu_ai_act": ["Article 10(2)(f), Article 15(3) (Bias detection & mitigation)"],
    },
    "policy_violation": {
        "owasp_llm_2025": ["LLM06:2025 Excessive Agency"],
        "nist_ai_rmf": ["GOVERN 1.3 (Policy compliance monitoring)"],
        "eu_ai_act": ["Article 13(3)(b) (Conformity with specifications)"],
    },
    "sponge_attack": {
        "owasp_llm_2025": ["LLM10:2025 Unbounded Consumption"],
        "mitre_atlas": ["AML.T0029: Denial of ML Service"],
        "nist_ai_rmf": ["MANAGE 4.1 (Resource management & availability)"],
        "eu_ai_act": ["Article 15(4) (Cybersecurity & resilience)"],
    },
    "keyword_detector": {
        "owasp_llm_2025": ["LLM01:2025 Prompt Injection (keyword filter)"],
        "nist_ai_rmf": ["MANAGE 2.3 (Content filtering)"],
    },
    "relevancy": {
        "owasp_llm_2025": ["LLM09:2025 Misinformation"],
        "nist_ai_rmf": ["MEASURE 2.6, MEASURE 2.13 (Output quality & appropriateness)"],
        "eu_ai_act": ["Article 15(1) (Accuracy & performance requirements)"],
    },
    "adherence": {
        "owasp_llm_2025": ["LLM06:2025 Excessive Agency", "LLM09:2025 Misinformation"],
        "nist_ai_rmf": ["MANAGE 1.3, MEASURE 1.1 (Performance monitoring against specs)"],
        "eu_ai_act": ["Article 13(3)(b) (Conformity with specifications)"],
    },
    "hallucination": {
        "owasp_llm_2025": ["LLM09:2025 Misinformation"],
        "nist_ai_rmf": ["MEASURE 2.6 (Output quality)"],
    },
}


def get_compliance_mapping(detector_name: str) -> dict[str, list[str]] | None:
    """Return compliance framework mappings for a given detector name."""
    return COMPLIANCE_MAP.get(detector_name)


def get_all_compliance_mappings() -> dict[str, dict[str, list[str]]]:
    """Return the full compliance mapping dictionary."""
    return COMPLIANCE_MAP
