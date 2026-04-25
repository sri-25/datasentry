# Known limitations

Things DataSentry does not do, with the reasoning for each. This is a
portfolio demo, not a production compliance tool — these limitations are
intentional tradeoffs, not unfinished work.

---

## Scope

### English only

The spaCy NER model (`en_core_web_sm`) and Claude's system prompt are
English-tuned. Spanish / French / Chinese / Hindi documents will return
only regex hits (structured identifiers like SSN, IBAN, VAT). Free-text
names and diagnoses won't be recognized.

**Why not multi-language?** Adds a language-detection step, per-language
NER models (~40MB each), and localized Claude prompts. Legitimate v3 work.

### English-centric NER coverage

Even within English, `en_core_web_sm` is trained on standard newswire
corpora — predominantly Western-origin, properly-cased names.

**Concrete failures:**

| Input | What happens | Why |
|---|---|---|
| `"given to mukesh"` | No detection | Lowercase, not surfaced by spaCy |
| `"given to Mukesh"` | No detection | Labeled as `GPE` (location), not PERSON — our pipeline filters GPE by design to avoid city-name FPs |
| `"given to John"` | Surfaced → Claude → dropped | Bare first name isn't PII under HIPAA/GDPR |
| `"Patient Mukesh"` | Surfaced → Claude → kept as `PHI` | Context anchor "Patient" helps spaCy classify correctly |

**Why not upgrade to `en_core_web_md` or `_trf`?** MD is 40MB (vs 15MB sm);
transformer-based `_trf` is 500MB+ and requires GPU for reasonable latency.
For the HF free-tier demo, small model is the right tradeoff. Self-hosters
can swap the model name in `app.py:18`.

### No OCR

PDFs must have extractable text. Scanned PDFs (images-of-text) return
empty strings with no error. This is the single most common failure mode
for real-world document scanning.

**Why not?** Adding Tesseract or PaddleOCR doubles the container size and
introduces per-page latency of 2–5 seconds. Worth it for production, not
for a portfolio demo.

### Pure prose without structured anchors

DataSentry is built for **structured business documents** — medical
records, HR files, contracts, support tickets, intake forms. These
naturally contain structured identifiers (SSN, DOB, account numbers, MRN,
ICD codes) that anchor the detection.

Pure free-form prose is out of scope. Concrete examples that return 0
entities:

- `"Mukesh called me yesterday"`
- `"John owns a large estate"`
- `"I am Mukesh and I have 3 billion USD in property"`

**Why?** A PII detector that fires on every bare name is useless in
practice — every chat log, every email, every tweet becomes "PII-flagged".
See `DECISIONS.md` §ADR-003 for the precision-vs-recall reasoning.

**Workaround if you need prose coverage:** combine DataSentry's output
with a recall-tuned pass from a larger model. The audit trail makes this
composable.

---

## Format-specific gotchas

| Format | Caveat |
|---|---|
| PDF | No OCR (above). Two-parser fallback: pdfplumber → pypdf |
| DOCX | Reads paragraphs + tables. **Ignores comments, tracked changes, footnotes, headers/footers** — these are often the most PII-rich parts of reviewed documents |
| XLSX | Reads cell values, **not formulas**. A cell containing `=VLOOKUP(A1, 'PHI_Sheet'!A:B, 2)` is invisible to us |
| CSV | Treated as flat text — no type inference, no column-header semantics |
| TXT | Straight read; no encoding auto-detect beyond UTF-8 with fallback |

**50,000 character cap per scan** (`CHAR_LIMIT` in `app.py`). Larger docs
are truncated with a warning banner. Not a fundamental limit — can be
raised or removed for self-hosters with proportional latency cost.

---

## Runtime

### Sequential Claude calls

Layer 3 processes ambiguous entities one at a time, round-tripping to the
Claude API. The patient-record PDF fixture takes ~9 seconds because it
has 8 ambiguous entities.

**Planned v3 fix:** batch ambiguous entities into one Claude call with a
structured list output. Expected speedup: 5–10× on entity-heavy docs.

### Ephemeral audit trail on HF Spaces

The SQLite database lives at `/tmp/datasentry_audit.db`, which HF Spaces
wipes on every container restart (typically every few hours when idle,
or on any redeploy). Audit data is live for the session, gone after.

Self-hosted or HF Spaces paid persistent storage → audit trail persists
correctly.

### Demo budget cap

Claude arbitration pauses once daily calls hit 500 (configurable via
`CLAUDE_DAILY_BUDGET` env var). Users will see a banner. Regex + spaCy
continue to work.

Not a limitation when self-hosting with your own API key and no cap.

---

## Not built, by design

- **No authentication.** Public demo. Self-hosted production needs auth.
- **No rate limiting per user.** HF's proxy means per-IP limits aren't
  reliable anyway. The daily budget cap is the blast-radius control.
- **No structured data export.** Redactions download as plain text or
  CSV. No JSON/XML export of detections. Trivial to add.
- **No model fine-tuning loop.** The `entity_feedback` table captures
  FP signals; using them to retrain Claude or the detection patterns is a
  v3 ML lifecycle story.
- **No enterprise integrations** (Slack webhooks, SIEM forwarding, S3
  archival, KMS-wrapped DB). All are standard follow-ons for production.

---

## What these limitations are worth

Each one is a defensible tradeoff with a clear reason. The portfolio
version of this project deliberately chooses:

- **Precision over recall** — 0 FP is more defensible than 95% recall
- **Small footprint over broad coverage** — 15MB spaCy, no OCR, no
  transformer NER
- **Single-machine deploy over multi-service** — SQLite over Postgres,
  in-process over API gateway

For a real production deployment, each of these flips. The *architecture*
is portable; the *deployment choices* are demo-appropriate.
