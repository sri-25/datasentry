# Coverage — what DataSentry detects

A practical contract of what flags, what doesn't, and why. Use this to
decide whether DataSentry fits your use case.

---

## Detected standalone (no other context required)

The Layer 1 regex pass catches these on their own — no surrounding text
is needed. These are the 30+ "high-recall" signals.

### US PII
| Entity | Example that flags alone | Detection |
|---|---|---|
| SSN | `SSN: 432-56-7890` | Regex, keyword-gated |
| Email | `alice@example.com` | Regex |
| Phone (US) | `(415) 555-2847` | Regex |
| Credit card | `4532015112830366` | Regex, Luhn-family patterns |
| IP address | `192.168.1.100` | Regex |
| US street address | `1842 Mission Street` | Regex, requires street-type suffix |
| ZIP code | `zip 94107` | Regex, keyword-gated |
| Date of birth | `DOB: 03/15/1978` | Regex, keyword-gated |
| US passport | `A12345678` | Regex, keyword-triggered |
| Bank account | `account number 8834291055` | Regex, keyword-gated |
| Routing number | `routing 021000021` | Regex, keyword-gated |
| IBAN | `DE89370400440532013000` | Regex |
| MAC address | `00:1A:2B:3C:4D:5E` | Regex |
| EIN | `EIN 12-3456789` | Regex, keyword-gated |
| Driver's license | `Driver's License CA: D8847291` | Regex, keyword + state + ID |

### US PHI
| Entity | Example that flags alone | Detection |
|---|---|---|
| NPI | `NPI 1234567893` | Regex, keyword-gated |
| MRN | `MRN-2024-00142` | Regex, keyword-gated |
| ICD-10 code | `E11.9` | Regex |
| DEA number | `DEA AB1234567` | Regex, keyword-gated |
| Insurance member ID | `member id MBR-2024-99182` | Regex, keyword-gated |

### International PII / PHI
| Entity | Example that flags alone | Detection |
|---|---|---|
| UK NIN | `NI: AB 12 34 56 C` | Regex, keyword-gated |
| UK NHS number | `NHS Number: 943 476 5919` | Regex, keyword-gated |
| Canadian SIN | `SIN: 123-456-789` | Regex, keyword-gated |
| Indian Aadhaar | `Aadhaar 1234 5678 9012` | Regex, keyword-gated |
| Indian PAN | `PAN ABCDE1234F` | Regex |
| Australian TFN | `TFN: 123 456 782` | Regex, keyword-gated |
| EU VAT | `VAT DE123456789` | Regex, keyword-gated |
| International phone | `+44 20 7946 0958` | Regex |

---

## Detected only *with* corroborating context

These require an anchor in the same ~300-character window. Claude
arbitrates to confirm the contextual linkage.

| Entity | Flags when | Does not flag when |
|---|---|---|
| **Person name** | In a medical record, HR file, customer record, or near an identifier (SSN, DOB, email, address) | As a bare first name in prose ("Hi John") |
| **Full name** | Paired with any identifier in context | In news prose or general reference |
| **Diagnosis keywords** (diabetes, cancer, etc.) | In a patient record tied to a named patient | In research, marketing, or population-statistic context |
| **Medication names** (metformin, lisinopril, etc.) | Explicitly prescribed or taken by a named patient | In research ("metformin's effect on outcomes"), educational content, or marketing copy |
| **Facility / hospital** | With patient details in context | As a bare location ("City Medical Center") |
| **Monetary values** | — | Always filtered (revenue figures are not PII under HIPAA/GDPR) |
| **Generic dates** | Linked to a named person as DOB / encounter date | As bare dates in prose |
| **Cities / locations** | — | Never flagged alone (HIPAA Safe Harbor exclusion) |

---

## Not detected at all

### By design
- Bare first names (`"John"`, `"Mukesh"`)
- Pure monetary values (`"3 billion USD"`)
- Locations alone (`"Boston"`, `"San Francisco"`)
- Dates alone (`"03/15/2024"`)
- Generic diagnosis references ("diabetes affects millions")
- Medication names in non-clinical context

### By current implementation
- Lowercase non-Western names ("mukesh" — spaCy sm limitation)
- Capitalized non-Western names when labeled as GPE by spaCy (see
  `LIMITATIONS.md`)
- Text in languages other than English
- Text inside images / scanned PDFs (no OCR)
- Values inside spreadsheet formulas
- Text inside DOCX comments or tracked changes

---

## Rule of thumb

**If your document contains any structured identifier** (SSN, email, phone,
credit card, MRN, ICD code, bank account, international ID, address) →
DataSentry will find it, plus will contextually flag nearby names and
diagnoses as PHI/PII.

**If your document is pure prose with no structured identifiers** → expect
near-zero detections. This is the intentional scope. Use a recall-tuned
whole-text LLM pass for that case.

---

## Worked examples

### High recall case — patient discharge summary
Input contains: SSN, MRN, DOB, ICD-10 codes, medications, NPI, email, phone.

Detected (12 entities):
`SSN` (regex), `DATE_OF_BIRTH` (regex), `MRN` (regex), `ICD_CODE` ×2 (regex),
`NPI` (regex), `EMAIL` (regex), `PHONE_US` (regex), `PATIENT_NAME_IN_MEDICAL_RECORD` (Claude),
`MEDICATION_PRESCRIBED` ×3 (Claude), `PROVIDER_NAME_IN_MEDICAL_RECORD` (Claude),
`DIAGNOSIS` ×2 (Claude).

### Zero-detection case — casual mention
Input: `"John has property worth 3 billion USD"`

Detected: 0 entities.
- `John` — spaCy surfaces → Claude drops ("bare first name, no corroborating identifier")
- `3 billion USD` — spaCy surfaces as MONEY → filtered (revenue figures not PII)

This is the *correct* HIPAA/GDPR-aligned behavior. A WSJ headline about a
billionaire isn't protected health information.

### Partial-recall case — research blog
Input: `"Boston Medical Center published a study on metformin. E11.9 is the ICD code for diabetes."`

Detected: 1 entity.
- `E11.9` (regex, high-confidence) — ICD codes flag standalone
- `Boston Medical Center` — filtered (hospital name alone, no patient context)
- `metformin` — Claude drops (research context, no named patient)
- `diabetes` — Claude drops (general reference, no patient)
