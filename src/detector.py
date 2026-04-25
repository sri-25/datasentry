"""
DataSentry v2 — Core Detection Engine
Layer 1: Regex
Layer 2: spaCy NER
Layer 3: Claude LLM arbitration (confidence < 0.75)
Layer 4: SQLite audit trail
"""

import os
import re
import time
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import spacy

from src.patterns import REGEX_PATTERNS
from src.audit import AuditLogger

logger = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = 0.75

# Daily Claude budget for the public demo. Guards against runaway cost
# if the HF Space gets scraped or spammed. Resets at UTC midnight. Tracked
# in the api_usage table — ephemeral on HF Spaces (/tmp) but persists on
# self-hosted deployments.
CLAUDE_DAILY_BUDGET = int(os.environ.get("CLAUDE_DAILY_BUDGET", "500"))

# ── Entity type blocklists ─────────────────────────────────────────────────────

# spaCy-detected entity types that are never PII/PHI on their own.
# Checks against the MAPPED entity_type (after _map_spacy_label),
# plus original spaCy labels as fallback.
SPACY_NON_PII_LABELS = {
    # Mapped types
    "LOCATION",      # from GPE, LOC — city/country alone is not PII
    "DATE",          # from DATE — date alone is not PII
    "NUMERIC",       # from CARDINAL — numbers are not PII
    "FINANCIAL",     # from MONEY — revenue figures are not PII
    "ORGANIZATION",  # from ORG — org name alone is not PII
    "FACILITY",      # from FAC — building name alone is not PHI
    # Original spaCy labels as fallback
    "GPE", "LOC", "CARDINAL", "MONEY", "ORG", "FAC",
    "TIME", "ORDINAL", "PERCENT", "QUANTITY",
    "PRODUCT", "EVENT", "WORK_OF_ART", "LANGUAGE",
    "LAW", "NORP",
}

# Regex-detected entity types that should be dropped before Claude
# unless they were already gated by a keyword in the pattern itself.
# These are inherently ambiguous without surrounding person context.
REGEX_SKIP_WITHOUT_CONTEXT = {
    "DATE_GENERIC",     # bare dates like 01/01/2024 are not PII alone
    "HOSPITAL_KEYWORD", # hospital name alone is not PHI
}

# Keyword prefixes to strip from matched text
# e.g. "SSN: 432-56-7890" → "432-56-7890"
_KEYWORD_PREFIX_RE = re.compile(
    r'^(?:ssn|social\s+security(?:\s+number)?|ss#|s\.s\.n\.?|'
    r'dob|date\s+of\s+birth|born\s+on|birthdate|'
    r'routing|aba|transit|routing\s+number|'
    r'zip|zip\s+code|postal\s+code|'
    r'mrn|medical\s+record\s+(?:number|#|no\.?)|'
    r'npi|national\s+provider(?:\s+identifier)?|'
    r'ein|employer\s+identification(?:\s+number)?|tax\s+id|'
    r'sin|social\s+insurance(?:\s+number)?|'
    r'tfn|tax\s+file(?:\s+number)?|'
    r'aadhaar|aadhar|uid|'
    r'pan|pan\s+(?:number|card)|'
    r'passport(?:\s+number)?|pass\s+no\.?|'
    r'dea|dea\s+number|'
    r'member\s*id|policy\s*(?:number|#)|insurance\s*(?:id|number)|'
    r'account\s*(?:number|#|no\.?)|acct\.?|'
    r'ni|national\s+insurance(?:\s+number)?|'
    r'nhs|nhs\s+number|'
    r'vat|vat\s+(?:number|id|reg)|'
    r'driver\'?s?\s+license|dl|license\s+number)'
    r'[\s:#\-]*',
    re.IGNORECASE
)


@dataclass
class Entity:
    entity_id: str
    text: str
    entity_type: str
    category: str
    start: int
    end: int
    confidence: float
    detection_layer: str
    rationale: str
    escalated: bool = False
    claude_override: bool = False


@dataclass
class DetectionResult:
    run_id: str
    source_text: str
    entities: list = field(default_factory=list)
    total_pii: int = 0
    total_phi: int = 0
    processing_ms: float = 0.0
    layers_used: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    # True when Claude arbitration was skipped for this run because the
    # daily budget was exhausted. Entities below the confidence threshold
    # are dropped in this case (conservative fallback).
    claude_skipped_budget: bool = False
    claude_calls_today: int = 0
    claude_budget_daily: int = 0


class DataSentryDetector:

    def __init__(self, spacy_model="en_core_web_sm", audit_db="datasentry_audit.db"):
        self.nlp = self._load_spacy(spacy_model)
        self.audit = AuditLogger(audit_db)
        logger.info("DataSentry v2 initialized")

    def _load_spacy(self, model_name):
        try:
            return spacy.load(model_name)
        except OSError:
            raise OSError(
                f"spaCy model '{model_name}' not found. "
                f"Run: python -m spacy download {model_name}"
            )

    def detect(self, text, source_label="unknown"):
        run_id = str(uuid.uuid4())
        start_time = time.time()
        result = DetectionResult(run_id=run_id, source_text=text)

        # Layer 1 — Regex
        regex_entities = self._layer1_regex(text)
        result.layers_used.append("regex")

        # Layer 2 — spaCy NER
        spacy_entities = self._layer2_spacy(text, existing=regex_entities)
        result.layers_used.append("spacy")

        # Merge all entities, resolve overlaps
        all_entities = self._merge_entities(regex_entities, spacy_entities)

        # Layer 3 — Claude arbitration for low-confidence entities.
        # Before entering the loop, check the daily budget once. If exhausted,
        # we drop all Claude-eligible entities (conservative) and set a flag
        # the UI uses to render a banner.
        result.claude_budget_daily = CLAUDE_DAILY_BUDGET
        result.claude_calls_today = self.audit.get_api_call_count("claude")
        budget_exhausted = result.claude_calls_today >= CLAUDE_DAILY_BUDGET

        final_entities = []
        for ent in all_entities:
            if ent.confidence < CONFIDENCE_THRESHOLD:

                # Guard 1 — drop spaCy non-PII labels before Claude
                # Checks mapped entity_type AND original spaCy labels
                if ent.detection_layer == "spacy" and ent.entity_type in SPACY_NON_PII_LABELS:
                    logger.debug(
                        "Skipping Claude for non-PII spaCy label: %s '%s'",
                        ent.entity_type, ent.text
                    )
                    continue  # drop entity entirely

                # Guard 2 — drop ambiguous regex entities before Claude
                # These are inherently noisy without person context
                if ent.detection_layer == "regex" and ent.entity_type in REGEX_SKIP_WITHOUT_CONTEXT:
                    logger.debug(
                        "Skipping Claude for low-value regex entity: %s '%s'",
                        ent.entity_type, ent.text
                    )
                    continue  # drop entity entirely

                # Budget guard — skip Claude entirely for the rest of this run.
                # Conservative: drop the low-confidence entity rather than
                # passing through a noisy spaCy / low-conf regex match.
                if budget_exhausted:
                    result.claude_skipped_budget = True
                    continue

                ent = self._layer3_claude(ent, text)
                # Count a successful Claude call against the daily budget
                result.claude_calls_today = self.audit.increment_api_call("claude")
                if "claude" not in result.layers_used:
                    result.layers_used.append("claude")

                # Guard 3 — drop entity if Claude says "not sensitive".
                # claude_override == False means Claude returned is_sensitive=false.
                # After the Claude call, entity.confidence reflects Claude's
                # confidence in its VERDICT — so a confident rejection still has
                # high confidence. We drop on the verdict, not the number.
                if not ent.claude_override:
                    logger.debug(
                        "Claude rejected entity: %s '%s' — %s",
                        ent.entity_type, ent.text, ent.rationale
                    )
                    continue  # drop from final results

            final_entities.append(ent)

        result.entities = final_entities
        result.total_pii = sum(1 for e in final_entities if e.category == "PII")
        result.total_phi = sum(1 for e in final_entities if e.category == "PHI")
        result.processing_ms = round((time.time() - start_time) * 1000, 2)

        # Layer 4 — SQLite audit trail
        self.audit.log(result, source_label)

        return result

    def detect_batch(self, texts, source_label="batch"):
        return [self.detect(t, source_label) for t in texts]

    def _layer1_regex(self, text):
        entities = []
        for pattern_def in REGEX_PATTERNS:
            for match in re.finditer(pattern_def["pattern"], text, re.IGNORECASE):
                # Strip leading keyword labels from matched text
                # e.g. "SSN: 432-56-7890" → "432-56-7890"
                # e.g. "DOB: 03/15/1978" → "03/15/1978"
                raw_text     = match.group()
                cleaned_text = _KEYWORD_PREFIX_RE.sub('', raw_text).strip()
                display_text = cleaned_text if cleaned_text else raw_text

                entities.append(Entity(
                    entity_id=str(uuid.uuid4()),
                    text=display_text,
                    entity_type=pattern_def["entity_type"],
                    category=pattern_def["category"],
                    start=match.start(),
                    end=match.end(),
                    confidence=pattern_def["base_confidence"],
                    detection_layer="regex",
                    rationale=f"Matched regex: {pattern_def['description']}",
                ))
        return entities

    def _layer2_spacy(self, text, existing):
        doc = self.nlp(text)
        existing_spans = [(e.start, e.end) for e in existing]

        spacy_entities = []
        for ent in doc.ents:
            overlaps = any(
                ent.start_char < e_end and ent.end_char > e_start
                for (e_start, e_end) in existing_spans
            )
            if overlaps:
                continue

            mapped = _map_spacy_label(ent.label_)
            if mapped is None:
                continue

            spacy_entities.append(Entity(
                entity_id=str(uuid.uuid4()),
                text=ent.text,
                entity_type=mapped["entity_type"],
                category=mapped["category"],
                start=ent.start_char,
                end=ent.end_char,
                confidence=mapped["confidence"],
                detection_layer="spacy",
                rationale=f"spaCy NER label: {ent.label_}",
            ))
        return spacy_entities

    def _layer3_claude(self, entity, full_text):
        from src.llm import claude_arbitrate
        ctx_start = max(0, entity.start - 150)
        ctx_end   = min(len(full_text), entity.end + 150)
        context   = full_text[ctx_start:ctx_end]

        try:
            result = claude_arbitrate(
                entity_text=entity.text,
                entity_type=entity.entity_type,
                context=context,
                current_confidence=entity.confidence,
            )
            entity.escalated       = True
            entity.detection_layer = "claude"

            if result["is_sensitive"]:
                entity.confidence      = result["confidence"]
                entity.entity_type     = result.get("refined_type", entity.entity_type)
                entity.category        = result.get("category", entity.category)
                entity.rationale       = result["rationale"]
                entity.claude_override = True
            else:
                entity.confidence      = result["confidence"]
                entity.rationale       = result["rationale"]
                entity.claude_override = False

        except Exception as e:
            logger.warning("Claude arbitration failed for '%s': %s", entity.text, e)
            entity.rationale += f" [Claude unavailable: {e}]"

        return entity

    def _merge_entities(self, *entity_lists):
        all_ents = [e for lst in entity_lists for e in lst]
        # Primary: confidence (high wins). Secondary: span length (long wins).
        # The length tiebreak ensures keyword-gated patterns like
        # "NHS Number: 943 476 5919" beat bare "943 476 5919" PHONE_US matches.
        all_ents.sort(key=lambda e: (e.confidence, e.end - e.start), reverse=True)

        merged = []
        taken  = []
        for ent in all_ents:
            overlaps = any(
                ent.start < t_end and ent.end > t_start
                for (t_start, t_end) in taken
            )
            if not overlaps:
                merged.append(ent)
                taken.append((ent.start, ent.end))

        return sorted(merged, key=lambda e: e.start)


# ── spaCy label → DataSentry entity type mapping ──────────────────────────────
#
# Confidence values are intentionally low for ambiguous labels (PERSON, ORG,
# GPE) so they always hit Claude arbitration threshold and get evaluated
# in context. SPACY_NON_PII_LABELS above drops pure location/date/number
# detections before they even reach Claude.

_SPACY_LABEL_MAP = {
    "PERSON":   {"entity_type": "PERSON_NAME",  "category": "PII", "confidence": 0.70},
    "ORG":      {"entity_type": "ORGANIZATION", "category": "PII", "confidence": 0.55},
    "GPE":      {"entity_type": "LOCATION",     "category": "PII", "confidence": 0.50},
    "LOC":      {"entity_type": "LOCATION",     "category": "PII", "confidence": 0.50},
    "DATE":     {"entity_type": "DATE",         "category": "PII", "confidence": 0.55},
    "CARDINAL": {"entity_type": "NUMERIC",      "category": "PII", "confidence": 0.45},
    "MONEY":    {"entity_type": "FINANCIAL",    "category": "PII", "confidence": 0.60},
    "FAC":      {"entity_type": "FACILITY",     "category": "PHI", "confidence": 0.55},
}


def _map_spacy_label(label):
    return _SPACY_LABEL_MAP.get(label)