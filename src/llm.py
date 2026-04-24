"""
DataSentry v2 — Layer 3: Claude LLM Arbitration
"""

import os
import json
import logging
import anthropic

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    global _client
    if _client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY not set. Add it to your .env file."
            )
        _client = anthropic.Anthropic(api_key=api_key)
    return _client


SYSTEM_PROMPT = """You are a PII/PHI classification expert in a data governance pipeline.

Decide whether a specific text fragment is sensitive personal or health information.

PII — data that identifies an individual:
  Names, SSNs, emails, phone numbers, addresses, DOBs, IP addresses, financial account numbers, credit cards.

PHI — health data linked to an individual:
  Diagnoses, medications, medical record numbers, treatment details, provider names in clinical context, insurance IDs, ICD codes.

Rules:
1. Consider the FULL CONTEXT — a date alone is not PII, but 'Patient DOB: 01/15/1980' is.
2. A keyword like 'diabetes' in a research paper is not PHI. 'Patient diagnosed with diabetes' is PHI.
3. When uncertain, err toward sensitive.
4. Respond ONLY with valid JSON. No preamble.

JSON schema:
{
  "is_sensitive": boolean,
  "confidence": float between 0.0 and 1.0,
  "category": "PII" or "PHI" or "NONE",
  "refined_type": string,
  "rationale": string (max 20 words)
}"""


def claude_arbitrate(entity_text, entity_type, context, current_confidence):
    client = _get_client()

    user_message = f"""Evaluate this entity:

Entity text: "{entity_text}"
Detected type: {entity_type}
Current confidence: {current_confidence:.2f}

Context:
---
{context}
---

Is this sensitive PII or PHI? Respond with JSON only."""

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = response.content[0].text.strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    parsed = json.loads(raw)

    required = ["is_sensitive", "confidence", "category", "refined_type", "rationale"]
    for field in required:
        if field not in parsed:
            raise ValueError(f"Claude response missing field: {field}")

    return parsed
