"""
DataSentry v2 — Core Detection Engine
Layer 1: Regex
Layer 2: spaCy NER
Layer 3: Claude LLM arbitration (confidence < 0.75)
Layer 4: SQLite audit trail
"""

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

        # Layer 1
        regex_entities = self._layer1_regex(text)
        result.layers_used.append("regex")

        # Layer 2
        spacy_entities = self._layer2_spacy(text, existing=regex_entities)
        result.layers_used.append("spacy")

        # Merge
        all_entities = self._merge_entities(regex_entities, spacy_entities)

        # Layer 3 — escalate low confidence to Claude
        final_entities = []
        for ent in all_entities:
            if ent.confidence < CONFIDENCE_THRESHOLD:
                ent = self._layer3_claude(ent, text)
                if "claude" not in result.layers_used:
                    result.layers_used.append("claude")
            final_entities.append(ent)

        result.entities = final_entities
        result.total_pii = sum(1 for e in final_entities if e.category == "PII")
        result.total_phi = sum(1 for e in final_entities if e.category == "PHI")
        result.processing_ms = round((time.time() - start_time) * 1000, 2)

        # Layer 4
        self.audit.log(result, source_label)

        return result

    def detect_batch(self, texts, source_label="batch"):
        return [self.detect(t, source_label) for t in texts]

    def _layer1_regex(self, text):
        entities = []
        for pattern_def in REGEX_PATTERNS:
            for match in re.finditer(pattern_def["pattern"], text, re.IGNORECASE):
                entities.append(Entity(
                    entity_id=str(uuid.uuid4()),
                    text=match.group(),
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
        ctx_end = min(len(full_text), entity.end + 150)
        context = full_text[ctx_start:ctx_end]

        try:
            result = claude_arbitrate(
                entity_text=entity.text,
                entity_type=entity.entity_type,
                context=context,
                current_confidence=entity.confidence,
            )
            entity.escalated = True
            entity.detection_layer = "claude"

            if result["is_sensitive"]:
                entity.confidence = result["confidence"]
                entity.entity_type = result.get("refined_type", entity.entity_type)
                entity.category = result.get("category", entity.category)
                entity.rationale = result["rationale"]
                entity.claude_override = True
            else:
                entity.confidence = result["confidence"]
                entity.rationale = result["rationale"]
                entity.claude_override = False

        except Exception as e:
            logger.warning("Claude arbitration failed for '%s': %s", entity.text, e)
            entity.rationale += f" [Claude unavailable: {e}]"

        return entity

    def _merge_entities(self, *entity_lists):
        all_ents = [e for lst in entity_lists for e in lst]
        all_ents.sort(key=lambda e: e.confidence, reverse=True)

        merged = []
        taken = []
        for ent in all_ents:
            overlaps = any(
                ent.start < t_end and ent.end > t_start
                for (t_start, t_end) in taken
            )
            if not overlaps:
                merged.append(ent)
                taken.append((ent.start, ent.end))

        return sorted(merged, key=lambda e: e.start)


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
