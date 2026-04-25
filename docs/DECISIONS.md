# Architecture Decisions

Short decision records for DataSentry's non-obvious design choices. Each
one captures *what was decided*, *why*, and *what it costs*.

---

## ADR-001: Hybrid 4-layer pipeline instead of "just ask an LLM"

**Decision.** Every input flows through regex → spaCy NER → Claude arbitration →
SQLite audit. Each layer is optional but compose in that order.

**Context.** The naive approach is to hand the whole document to a large model
and ask for PII/PHI. It works, but it's slow, expensive, and produces
inconsistent results across runs.

**Rationale.**

- **Regex is essentially free.** Structured identifiers (SSN, credit cards,
  ICD codes, IBAN) have a known shape. A 50-pattern regex pass over a 5KB
  document runs in milliseconds and catches 60–70% of real detections.
- **spaCy NER handles free-text.** Names, organizations, and addresses don't
  have a deterministic shape — an NER model is the right tool. `en_core_web_sm`
  is 15MB and fast.
- **LLMs earn their keep as arbiters, not detectors.** Context-dependent
  decisions ("is 'metformin' sensitive here?") are where LLMs shine. Running
  Claude on *every* token would cost 100× more for the same precision.
- **Audit is non-negotiable.** Compliance-grade tools need provenance per
  decision. SQLite writes are cheap and the schema is portable.

**Tradeoff.** More code to maintain than a single-model pipeline. Three
failure modes (regex, NER, LLM) instead of one. Worth it for the cost and
auditability wins.

---

## ADR-002: Claude as arbiter, not primary detector

**Decision.** Claude sees an entity only if (a) regex or spaCy already
proposed it, and (b) its confidence is below 0.75.

**Context.** An alternative is to chunk the document and feed every chunk to
Claude with a "find all PII/PHI" prompt. Tempting, but bad.

**Rationale.**

- **Cost scales with entities, not document size.** A 5KB patient note with
  10 ambiguous entities triggers 10 Claude calls. The same note fed whole to
  an LLM would spend tokens on every word whether or not it's sensitive.
- **Arbitration is a constrained task.** "Is this specific fragment PII given
  this context?" is a small, well-defined question. LLMs are reliable at
  small questions and unreliable at open-ended ones.
- **The confidence threshold is deliberate.** High-confidence regex matches
  (SSN 0.95, credit card 0.95) skip Claude entirely — they're already
  structural. Medium-confidence regex (MEDICATION 0.68, ICD_CODE 0.92) and
  spaCy guesses (PERSON_NAME 0.70) need the context check.

**Tradeoff.** The pipeline can't flag things neither regex nor spaCy surfaces.
That's a real coverage gap — see `LIMITATIONS.md` for the "Mukesh" case. The
cost side of the tradeoff is: for every 1 ambiguity Claude handles, it avoids
~50 LLM calls that would have fired on certain matches.

---

## ADR-003: Precision over recall — bare names are not PII

**Decision.** When Claude evaluates a person name with no corroborating
identifier in context, it returns `is_sensitive: false`. The entity is dropped.

**Context.** A test case: `"John has property worth 3 billion USD"`. Intuition
says this is "about a person", but the pipeline returns 0 entities. Bug or
feature?

**Rationale.**

- **"John" alone identifies ~16 million Americans.** HIPAA's Safe Harbor
  and GDPR's "reasonably identifiable" test both require linkage to a
  specific individual. A bare first name fails that test.
- **Flagging bare names destroys trust.** A PII tool that triggers on every
  "Hi John" in an email thread is useless. Users turn it off within a day.
- **Real documents have anchors.** Medical records, HR files, contracts,
  bank statements — all contain structured identifiers (SSN, DOB, MRN,
  account numbers). When the anchor is present, Claude refines nearby names
  to `PERSON_NAME_IN_MEDICAL_RECORD` / `PERSON_NAME_WITH_IDENTIFIERS` etc.
  Recall is high *in documents where it matters*.

**Tradeoff.** Free-form prose like *"Mukesh called me yesterday"* or
*"John owns property worth 3B"* returns 0 entities. The pipeline is
deliberately narrow — see `COVERAGE.md` for the explicit contract.

---

## ADR-004: SQLite audit, not an external database

**Decision.** All audit logging uses SQLite, co-located with the app.

**Context.** Production privacy tools typically log to Postgres, Kafka, or a
dedicated audit service.

**Rationale.**

- **Zero-config for self-hosters.** `git clone && pip install && python app.py`
  produces a working audit trail with no external dependencies.
- **Schema is portable.** The three tables (`detection_runs`,
  `detected_entities`, `entity_feedback`) map cleanly to any RDBMS. Swapping
  the connection string is the only change required.
- **Query-able with `sqlite3`.** Operators can inspect the audit trail from
  a shell without installing anything.

**Tradeoff.** Single-writer bottleneck at high concurrency. For the demo and
small self-hosted deployments, fine. For multi-tenant SaaS, migrate to
Postgres — the code expects it.

---

## ADR-005: Drop on Claude rejection, regardless of Claude's confidence

**Decision.** If Claude returns `is_sensitive: false` for an arbitrated
entity, drop the entity. Don't read Claude's reported confidence.

**Context.** The first version of the guard said
`if not claude_override and confidence < 0.5: drop`. Tests revealed that
Claude's returned `confidence` refers to its *own verdict*, not the
probability of sensitivity. A confident rejection (`is_sensitive: false,
confidence: 0.95`) meant "I'm 95% sure this is not sensitive" — but the
guard read it as "high probability of sensitivity" and kept it.

**Rationale.**

- **The verdict is what matters.** Claude saying "not sensitive" is the
  signal. The confidence number is metadata about its internal certainty,
  not an input to the drop decision.
- **Caught by live tests.** The bug was invisible to regex-only unit tests
  because the Claude layer wasn't exercised. `@pytest.mark.live` tests with
  the actual API surfaced it. Worth the cost of running a few cents of API
  calls in CI.

**Tradeoff.** Claude's reported `confidence` is now unused in the drop path.
That's fine — the verdict is categorical (keep / drop), not a probability.
Future versions might use the confidence to weight audit-log rationale,
but never as a gate.

---

## ADR-006: Daily budget cap on LLM arbitration

**Decision.** The Claude layer stops firing once daily calls hit a
configurable cap (default 500 / 24h UTC). Remaining entities in the scan
are conservatively dropped; the UI shows a banner.

**Context.** The HF Spaces demo is public and unauthenticated. One bad
actor with a script could burn the entire monthly API budget in minutes.

**Rationale.**

- **Graceful degradation over hard failure.** Regex + spaCy keep working
  even when Claude is paused — the demo is still useful.
- **Visible in UI.** The banner "Claude arbitration paused — daily budget
  reached" tells the user *why* they're seeing fewer entities, not that
  the tool is broken.
- **Cheap to implement.** One `api_usage` table, two methods (`get_count`,
  `increment`), one branch in the pipeline. No external rate limiter, no
  token bucket.

**Tradeoff.** The counter lives in SQLite and is ephemeral on HF Spaces
(`/tmp`). Container restart resets it. For abuse-prevention that's actually
a feature — a restart costs the attacker their cooldown. For production
self-hosters, the counter persists correctly.
