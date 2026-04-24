"""
DataSentry v2 — FastAPI Application
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from src.detector import DataSentryDetector, DetectionResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

detector = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global detector
    from dotenv import load_dotenv
    load_dotenv()
    logger.info("Loading DataSentry v2...")
    detector = DataSentryDetector(
        spacy_model=os.environ.get("SPACY_MODEL", "en_core_web_sm"),
        audit_db=os.environ.get("AUDIT_DB_PATH", "datasentry_audit.db"),
    )
    logger.info("DataSentry v2 ready.")
    yield


app = FastAPI(
    title="DataSentry v2",
    description="Hybrid PII/PHI detection engine",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class DetectRequest(BaseModel):
    text: str
    source_label: str = "api"


class BatchDetectRequest(BaseModel):
    texts: list
    source_label: str = "batch_api"


class EntityOut(BaseModel):
    entity_id: str
    text: str
    entity_type: str
    category: str
    start: int
    end: int
    confidence: float
    detection_layer: str
    rationale: str
    escalated: bool
    claude_override: bool


class DetectResponse(BaseModel):
    run_id: str
    total_pii: int
    total_phi: int
    entity_count: int
    processing_ms: float
    layers_used: list
    entities: list
    timestamp: str


def _format(result: DetectionResult) -> DetectResponse:
    return DetectResponse(
        run_id=result.run_id,
        total_pii=result.total_pii,
        total_phi=result.total_phi,
        entity_count=len(result.entities),
        processing_ms=result.processing_ms,
        layers_used=list(set(result.layers_used)),
        timestamp=result.timestamp,
        entities=[
            {
                "entity_id": e.entity_id,
                "text": e.text,
                "entity_type": e.entity_type,
                "category": e.category,
                "start": e.start,
                "end": e.end,
                "confidence": round(e.confidence, 4),
                "detection_layer": e.detection_layer,
                "rationale": e.rationale,
                "escalated": e.escalated,
                "claude_override": e.claude_override,
            }
            for e in result.entities
        ],
    )


@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0", "service": "DataSentry"}


@app.post("/detect")
async def detect(req: DetectRequest):
    try:
        result = detector.detect(req.text, source_label=req.source_label)
        return _format(result)
    except Exception as e:
        logger.exception("Detection failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect/batch")
async def detect_batch(req: BatchDetectRequest):
    try:
        results = detector.detect_batch(req.texts, source_label=req.source_label)
        return [_format(r) for r in results]
    except Exception as e:
        logger.exception("Batch detection failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit/runs")
async def get_runs(limit: int = Query(50, ge=1, le=500)):
    return detector.audit.get_recent_runs(limit=limit)


@app.get("/audit/run/{run_id}")
async def get_run(run_id: str):
    run = detector.audit.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Run {run_id} not found")
    entities = detector.audit.get_entities_for_run(run_id)
    return {"run": run, "entities": entities}


@app.get("/audit/stats")
async def get_stats():
    return detector.audit.get_stats()


@app.get("/audit/search")
async def search_entities(
    entity_type: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(100, ge=1, le=1000),
):
    return detector.audit.search_entities(
        entity_type=entity_type,
        category=category,
        min_confidence=min_confidence,
        limit=limit,
    )
