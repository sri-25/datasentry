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


SYSTEM_PROMPT = """You are a precise PII/PHI classification engine embedded in a data governance pipeline.

Your sole job: decide whether a specific text fragment is genuinely sensitive personal or health information requiring protection under HIPAA, GDPR, or equivalent privacy regulation.

━━━ WHAT COUNTS AS PII ━━━
Only flag if the text DIRECTLY identifies or could uniquely identify a living individual:
  • Government IDs: SSN, passport, driver's license, national ID numbers
  • Contact identifiers: email addresses, phone numbers, physical addresses
  • Biometric or account identifiers: IP addresses tied to a user, credit cards, bank accounts
  • Date of birth — ONLY when explicitly tied to a named or identified person

━━━ WHAT COUNTS AS PHI ━━━
Only flag if the text is health data AND is linked (explicitly or by context) to a specific individual:
  • Clinical: diagnoses, medications, treatments, lab results — tied to a patient
  • Administrative: MRN, NPI, insurance ID, ICD codes — in a medical record context
  • Provider names — ONLY when appearing in a patient record, not in general text

━━━ DO NOT FLAG THESE — THEY ARE NOT PII OR PHI ━━━
  • City, state, country, or region names alone (Boston, California, India)
  • Hospital or clinic names without patient context (City Medical Center alone)
  • Generic date ranges not tied to a person (01/01/2024, "last quarter", "this year")
  • Revenue figures, dollar amounts, financial metrics not linked to an individual
  • Diagnosis keywords in general, educational, marketing, or research context
    ("diabetes affects 10% of adults", "Cancer Research Has Evolved", "Type 2
    diabetes is a growing concern") — NO INDIVIDUAL = NOT PHI
  • Medication names in general, educational, marketing, or research context
    ("metformin's effect on long-term outcomes", "common drugs include lisinopril")
    — only flag medications when explicitly prescribed/taken by a named patient
  • Product names, serial numbers, version numbers, order IDs
  • Common nouns that pattern-match but carry no individual identity
    (e.g. "Medications", "Anonymous", "Patient" — these are headers/labels, not names)
  • Numbers that are clearly counts, measurements, or identifiers for non-persons

━━━ DECISION RULE ━━━
Ask yourself: "If I saw only this fragment, could I identify or re-identify a specific living person?"
  → YES with high confidence  : is_sensitive = true
  → MAYBE or NOT SURE         : is_sensitive = false  (default to not sensitive)
  → NO                        : is_sensitive = false

When uncertain — default to NOT sensitive. False negatives in edge cases are preferable
to false positives that erode user trust in the system.

━━━ WORKED EXAMPLES ━━━

Example 1 — medication in research/marketing context (NOT sensitive):
  Entity: "metformin"
  Context: "Boston Medical Center recently published a study on metformin's effect
            on long-term outcomes."
  → {"is_sensitive": false, "confidence": 0.95, "category": "NONE",
     "refined_type": "NONE", "rationale": "Medication in research context, no patient"}

Example 2 — medication in patient record (IS sensitive):
  Entity: "metformin"
  Context: "Patient John Smith was prescribed metformin 500mg BID after his E11.9
            diagnosis."
  → {"is_sensitive": true, "confidence": 0.95, "category": "PHI",
     "refined_type": "MEDICATION_PRESCRIBED", "rationale": "Medication tied to named patient"}

Example 3 — common noun triggered by spaCy (NOT sensitive):
  Entity: "Medications"
  Context: "Medications prescribed at discharge:"
  → {"is_sensitive": false, "confidence": 0.98, "category": "NONE",
     "refined_type": "NONE", "rationale": "Section header, not a person name"}

Example 4 — city name alone (NOT sensitive):
  Entity: "Boston"
  Context: "Our offices are in San Francisco, Austin, and Boston."
  → {"is_sensitive": false, "confidence": 0.95, "category": "NONE",
     "refined_type": "NONE", "rationale": "City name without individual linkage"}

Example 5 — diagnosis in educational content (NOT sensitive):
  Entity: "diabetes"
  Context: "Type 2 diabetes affects roughly 37 million Americans."
  → {"is_sensitive": false, "confidence": 0.95, "category": "NONE",
     "refined_type": "NONE", "rationale": "Diagnosis keyword in population statistic"}

━━━ OUTPUT ━━━
Respond ONLY with valid JSON. No preamble, no explanation, no markdown fences.

{
  "is_sensitive": boolean,
  "confidence": float between 0.0 and 1.0,
  "category": "PII" or "PHI" or "NONE",
  "refined_type": string (e.g. "SSN", "DATE_OF_BIRTH", "DIAGNOSIS", "NONE"),
  "rationale": string (max 15 words — be specific about why or why not)
}"""


def claude_arbitrate(entity_text, entity_type, context, current_confidence):
    client = _get_client()

    user_message = f"""Evaluate this detected entity:

Entity text: "{entity_text}"
Detected type: {entity_type}
Current confidence: {current_confidence:.2f}

Surrounding context (50 chars each side):
---
{context}
---

Is this genuinely sensitive PII or PHI? Respond with JSON only."""

    try:
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

        logger.debug(
            "Claude arbitration: '%s' (%s) → %s (%.0f%%) — %s",
            entity_text,
            entity_type,
            parsed["refined_type"],
            parsed["confidence"] * 100,
            parsed["rationale"],
        )

        return parsed

    except json.JSONDecodeError as e:
        logger.warning("Claude returned invalid JSON for '%s': %s", entity_text, e)
        # Fail safe — return not sensitive rather than crashing the pipeline
        return {
            "is_sensitive": False,
            "confidence": 0.0,
            "category": "NONE",
            "refined_type": "PARSE_ERROR",
            "rationale": "Claude response could not be parsed",
        }
    except Exception as e:
        logger.warning("Claude arbitration failed for '%s': %s", entity_text, e)
        # Fail safe — preserve original detection rather than crashing
        return {
            "is_sensitive": current_confidence >= 0.75,
            "confidence": current_confidence,
            "category": "PII",
            "refined_type": entity_type,
            "rationale": "Claude unavailable — using regex confidence",
        }