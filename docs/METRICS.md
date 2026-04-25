# Measured performance

Numbers below come from the end-to-end UAT smoke test against 6 realistic
fixtures across all supported formats, plus the 41-test pytest suite. Rerun
yourself with:

```bash
python tests/smoke_test.py       # end-to-end over fixtures
pytest tests/ -m "not live"      # 39 unit + integration tests (~6s)
pytest tests/ -m live            # 2 live Claude regression tests (~7s)
```

---

## Smoke test: 6 realistic fixtures

| Fixture | Format | Entities expected | Detected | FPs |
|---|---|---:|---:|---:|
| `patient_discharge.pdf` | PDF | 12 | 12 | 0 |
| `customer_roster.xlsx` | XLSX | 6 | 6 | 0 |
| `hr_onboarding.docx` | DOCX | 8 | 8 | 0 |
| `support_tickets.csv` | CSV | 4 | 4 | 0 |
| `marketing_blog.txt` | TXT (FP-bait) | 1 | 1 | 0 |
| `international_compliance.txt` | TXT | 8 | 8 | 0 |
| **Totals** | | **39** | **39** | **0** |

*Recall is reported on entity presence; type labels are sometimes refined
by Claude (e.g., `PERSON_NAME` → `PATIENT_NAME_IN_MEDICAL_RECORD`). Refined
types are counted as detected.*

**Key results:**

- **Recall: ~100% of in-scope entities** across formats
- **False positive rate: 0** after the FP-engineering work (was 2.5% before)
- **International ID coverage: 8/8** on a mixed fixture (UK NIN, UK NHS,
  Indian Aadhaar, Indian PAN, Canadian SIN, Australian TFN, EU VAT, email)

**FP-engineering iterations measured:**

1. `mettformin` in a research blog: 1 FP → fixed with Claude prompt few-shot examples (0 FP)
2. NHS number mislabeled as `PHONE_US`: fixed with length-tiebreak in merge (0 collision)
3. `'Medications'` (plural noun) flagged as a person name: fixed with Claude
   guard correction (0 FP on common-noun triggers)

---

## Latency

Wall-clock over 6 fixtures, median-of-3 runs:

| Path | Total (6 fixtures) | Per-fixture median | Per-fixture p95 |
|---|---:|---:|---:|
| Full pipeline (regex + spaCy + Claude) | 21.2 s | 3.5 s | 10 s |
| No Claude needed (high-conf regex only) | 0.08 s | 40 ms | 90 ms |

The 10s p95 is the patient-discharge PDF, which triggers 6–8 sequential
Claude arbitration calls. This is the biggest latency lever — see
`LIMITATIONS.md` §"Sequential Claude calls" for v3 plans.

---

## Test suite: 41 tests, ~7s total

| Category | Tests | Runtime |
|---|---:|---:|
| Regex pattern recall (keyword-gated) | 23 | <1 s |
| Regex-shape regressions (paren, span, context) | 3 | <1 s |
| Merge / overlap resolution | 3 | <1 s |
| End-to-end (no Claude) | 4 | ~1 s |
| Budget cap behaviour | 4 | <1 s |
| Data model sanity | 2 | <1 s |
| **Live Claude** (opt-in) | 2 | ~7 s |
| **Total** | **41** | **~7 s** |

Runs with `pytest tests/` (skips the 2 live tests by default) in ~6 s.
Runs with `pytest tests/ -m live` to include live Claude regression tests
in ~7 s (costs a few cents of API credits).

**Coverage notes:**

- Every keyword-gated regex has a positive case AND a negative case (bare
  digits without keyword must not match)
- Regex regression tests capture the three bugs found by the smoke test
  (PHONE_US paren stripping, DRIVER_LICENSE span truncation, NHS/PHONE
  collision)
- Live tests cover both sides of the medication-in-context decision
  (research → drop, patient record → keep)

---

## Cost — projected

Based on Claude Haiku 4.5 pricing (~$1 per million input tokens, ~$5 per
million output):

- **Per scan (average):** 3 ambiguous entities × ~500 input + 150 output tokens = 1.95k input + 450 output tokens
- **Per scan cost:** ~$0.005 (half a cent)
- **$1 of credit ≈ 200 scans**
- **$5/month ≈ 1,000 scans** (generous for a portfolio demo)

Daily budget cap defaults to 500 Claude calls (~167 scans average), which
puts the monthly ceiling at ~$0.25/day = $7.50/month worst case.
