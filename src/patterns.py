"""
DataSentry v2 — Regex Pattern Library (Layer 1)

Coverage:
  - US PII: SSN, email, phone, credit card, address, passport, bank
  - US PHI: MRN, NPI, ICD-10, DEA, insurance ID, medications, diagnoses
  - International: UK NIN, EU VAT, Canadian SIN, Indian Aadhaar,
                   Australian TFN, IBAN, generic passport

False positive mitigations (v2.1):
  - SSN now requires keyword context (ssn/social security) to avoid
    matching phone numbers and serial numbers
  - ZIP_CODE requires keyword context
  - ROUTING_NUMBER requires keyword context
  - DATE_GENERIC confidence lowered to 0.30 (always sent to Claude)
  - HOSPITAL_KEYWORD confidence lowered to 0.40
"""

REGEX_PATTERNS = [

    # ── US PII — Identity ──────────────────────────────────────────────────

    {
        "entity_type": "SSN",
        "category": "PII",
        "base_confidence": 0.95,
        "description": "US Social Security Number — keyword context required",
        # Requires ssn/social security keyword nearby to avoid phone FPs
        "pattern": r"\b(?:ssn|social\s+security(?:\s+number)?|ss#|s\.s\.n\.?)[\s:#\-]*(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
    },
    {
        "entity_type": "EMAIL",
        "category": "PII",
        "base_confidence": 0.93,
        "description": "Email address",
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    },
    {
        "entity_type": "PHONE_US",
        "category": "PII",
        "base_confidence": 0.90,
        "description": "US phone number",
        "pattern": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
    },
    {
        "entity_type": "CREDIT_CARD",
        "category": "PII",
        "base_confidence": 0.95,
        "description": "Credit card number (Visa, MC, Amex, Discover)",
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    },
    {
        "entity_type": "IP_ADDRESS",
        "category": "PII",
        "base_confidence": 0.85,
        "description": "IPv4 address",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    },
    {
        "entity_type": "US_ADDRESS",
        "category": "PII",
        "base_confidence": 0.82,
        "description": "US street address",
        "pattern": r"\b\d{1,5}\s+(?:[A-Za-z0-9]+\s){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
    },
    {
        "entity_type": "ZIP_CODE",
        "category": "PII",
        "base_confidence": 0.78,
        "description": "US ZIP code — keyword context required",
        # Requires zip/postal keyword to avoid matching any 5-digit number
        "pattern": r"\b(?:zip|zip\s+code|postal\s+code)[\s:#]*\d{5}(?:[-\s]\d{4})?\b",
    },
    {
        "entity_type": "DATE_OF_BIRTH",
        "category": "PII",
        "base_confidence": 0.92,
        "description": "Date of birth — keyword triggered",
        "pattern": r"\b(?:dob|date\s+of\s+birth|born\s+on|birthdate|birth\s+date)[\s:]+\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b",
    },
    {
        "entity_type": "DATE_GENERIC",
        "category": "PII",
        "base_confidence": 0.30,
        "description": "Generic date — very low confidence, always reviewed by Claude",
        # Lowered from 0.50 to 0.30 so Claude always evaluates context
        "pattern": r"\b\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b",
    },
    {
        "entity_type": "PASSPORT_US",
        "category": "PII",
        "base_confidence": 0.88,
        "description": "US Passport number",
        "pattern": r"\b[A-Z]{1}[0-9]{8}\b",
    },
    {
        "entity_type": "BANK_ACCOUNT",
        "category": "PII",
        "base_confidence": 0.80,
        "description": "Bank account number — keyword context required",
        "pattern": r"\b(?:account\s*(?:number|#|no\.?)|acct\.?)[\s:#]*\d{8,17}\b",
    },
    {
        "entity_type": "ROUTING_NUMBER",
        "category": "PII",
        "base_confidence": 0.88,
        "description": "US ABA routing number — keyword context required",
        # Requires routing/aba/transit keyword to avoid matching any 9-digit number
        "pattern": r"\b(?:routing|aba|transit|routing\s+number)[\s:#]*[0123]\d{8}\b",
    },
    {
        "entity_type": "IBAN",
        "category": "PII",
        "base_confidence": 0.92,
        "description": "International Bank Account Number",
        "pattern": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b",
    },
    {
        "entity_type": "MAC_ADDRESS",
        "category": "PII",
        "base_confidence": 0.90,
        "description": "MAC address",
        "pattern": r"\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b",
    },
    {
        "entity_type": "EIN",
        "category": "PII",
        "base_confidence": 0.88,
        "description": "US Employer Identification Number",
        "pattern": r"\b(?:ein|employer\s+identification(?:\s+number)?|tax\s+id)[\s:#]*\d{2}[-\s]?\d{7}\b",
    },
    {
        "entity_type": "DRIVERS_LICENSE_US",
        "category": "PII",
        "base_confidence": 0.82,
        "description": "US Driver's License — keyword triggered",
        "pattern": r"\b(?:driver'?s?\s+license|dl|license\s+number)[\s:#]*[A-Z0-9]{6,12}\b",
    },

    # ── US PHI — Medical ───────────────────────────────────────────────────

    {
        "entity_type": "NPI",
        "category": "PHI",
        "base_confidence": 0.90,
        "description": "National Provider Identifier",
        "pattern": r"\b(?:NPI|national\s+provider(?:\s+identifier)?)[\s:#]*\d{10}\b",
    },
    {
        "entity_type": "MRN",
        "category": "PHI",
        "base_confidence": 0.88,
        "description": "Medical Record Number",
        "pattern": r"\b(?:MRN|medical\s+record\s+(?:number|#|no\.?))[\s:#]*[A-Z0-9\-]{5,15}\b",
    },
    {
        "entity_type": "ICD_CODE",
        "category": "PHI",
        "base_confidence": 0.92,
        "description": "ICD-10 diagnostic code",
        "pattern": r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b",
    },
    {
        "entity_type": "DEA_NUMBER",
        "category": "PHI",
        "base_confidence": 0.93,
        "description": "DEA registration number",
        "pattern": r"\b(?:DEA|dea\s+number)[\s:#]*[A-Z]{2}\d{7}\b",
    },
    {
        "entity_type": "HEALTH_INSURANCE_ID",
        "category": "PHI",
        "base_confidence": 0.85,
        "description": "Health insurance member ID",
        "pattern": r"\b(?:member\s*id|policy\s*(?:number|#)|insurance\s*(?:id|number))[\s:#]*[A-Z0-9\-]{6,20}\b",
    },
    {
        "entity_type": "PHI_DIAGNOSIS_KEYWORD",
        "category": "PHI",
        "base_confidence": 0.65,
        "description": "Clinical diagnosis keyword — needs Claude review",
        "pattern": r"\b(?:diagnosis|diagnosed\s+with|condition|disorder|syndrome|disease|cancer|diabetes|hypertension|depression|anxiety|HIV|AIDS|hepatitis)\b",
    },
    {
        "entity_type": "MEDICATION",
        "category": "PHI",
        "base_confidence": 0.68,
        "description": "Common medication names — needs Claude review",
        "pattern": r"\b(?:metformin|lisinopril|atorvastatin|levothyroxine|omeprazole|amlodipine|metoprolol|albuterol|gabapentin|sertraline|fluoxetine|amoxicillin|ibuprofen|warfarin|insulin|prednisone|hydrochlorothiazide|losartan|simvastatin|azithromycin)\b",
    },
    {
        "entity_type": "HOSPITAL_KEYWORD",
        "category": "PHI",
        "base_confidence": 0.40,
        "description": "Hospital/clinic keyword — needs Claude review",
        # Lowered from 0.60 to 0.40 — location alone is not PHI without patient context
        "pattern": r"\b(?:hospital|medical\s+center|clinic|healthcare|health\s+system|urgent\s+care|emergency\s+room|ER|ICU|OR)\b",
    },

    # ── International PII ──────────────────────────────────────────────────

    {
        "entity_type": "UK_NIN",
        "category": "PII",
        "base_confidence": 0.92,
        "description": "UK National Insurance Number",
        # Format: XX 99 99 99 X — two letters, six digits, one letter
        "pattern": r"\b(?:NI|national\s+insurance(?:\s+number)?)[\s:#]*[A-CEGHJ-PR-TW-Z]{2}\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D]\b",
    },
    {
        "entity_type": "UK_NHS_NUMBER",
        "category": "PHI",
        "base_confidence": 0.90,
        "description": "UK NHS Number",
        # Format: 10 digits, often written as 3-3-4
        "pattern": r"\b(?:NHS|nhs\s+number)[\s:#]*\d{3}[-\s]?\d{3}[-\s]?\d{4}\b",
    },
    {
        "entity_type": "CANADIAN_SIN",
        "category": "PII",
        "base_confidence": 0.90,
        "description": "Canadian Social Insurance Number",
        # Format: 999-999-999
        "pattern": r"\b(?:SIN|social\s+insurance(?:\s+number)?)[\s:#]*\d{3}[-\s]?\d{3}[-\s]?\d{3}\b",
    },
    {
        "entity_type": "INDIAN_AADHAAR",
        "category": "PII",
        "base_confidence": 0.88,
        "description": "Indian Aadhaar number",
        # Format: 12 digits, often written as 4-4-4
        "pattern": r"\b(?:aadhaar|aadhar|uid)[\s:#]*\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
    },
    {
        "entity_type": "INDIAN_PAN",
        "category": "PII",
        "base_confidence": 0.92,
        "description": "Indian PAN (Permanent Account Number)",
        # Format: AAAAA9999A — 5 letters, 4 digits, 1 letter
        "pattern": r"\b(?:PAN|pan\s+(?:number|card))?[\s:#]*[A-Z]{5}\d{4}[A-Z]\b",
    },
    {
        "entity_type": "AUSTRALIAN_TFN",
        "category": "PII",
        "base_confidence": 0.90,
        "description": "Australian Tax File Number",
        # Format: 8 or 9 digits
        "pattern": r"\b(?:TFN|tax\s+file(?:\s+number)?)[\s:#]*\d{3}[-\s]?\d{3}[-\s]?\d{2,3}\b",
    },
    {
        "entity_type": "EU_VAT",
        "category": "PII",
        "base_confidence": 0.88,
        "description": "EU VAT registration number",
        # Format: 2-letter country code + 8-12 alphanumeric chars
        "pattern": r"\b(?:VAT|vat\s+(?:number|id|reg))[\s:#]*[A-Z]{2}[0-9A-Za-z]{8,12}\b",
    },
    {
        "entity_type": "PASSPORT_GENERIC",
        "category": "PII",
        "base_confidence": 0.85,
        "description": "Generic international passport number — keyword triggered",
        "pattern": r"\b(?:passport(?:\s+number)?|pass\s+no\.?)[\s:#]*[A-Z0-9]{6,9}\b",
    },
    {
        "entity_type": "PHONE_INTERNATIONAL",
        "category": "PII",
        "base_confidence": 0.82,
        "description": "International phone number with country code",
        # Matches +44, +91, +61, +33 etc followed by digits
        "pattern": r"\+(?!1\b)(?:[1-9]\d{0,2})[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}[-.\s]?\d{0,4}\b",
    },
]