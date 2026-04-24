"""
DataSentry v2 — Regex Pattern Library (Layer 1)
"""

REGEX_PATTERNS = [

    # PII — Identity
    {
        "entity_type": "SSN",
        "category": "PII",
        "base_confidence": 0.95,
        "description": "US Social Security Number",
        "pattern": r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
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
        "pattern": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    },
    {
        "entity_type": "CREDIT_CARD",
        "category": "PII",
        "base_confidence": 0.95,
        "description": "Credit card number",
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
        "description": "US ZIP code",
        "pattern": r"\b\d{5}(?:[-\s]\d{4})?\b",
    },
    {
        "entity_type": "DATE_OF_BIRTH",
        "category": "PII",
        "base_confidence": 0.72,
        "description": "Date of birth — keyword triggered",
        "pattern": r"\b(?:dob|date\s+of\s+birth|born\s+on|birthdate)[\s:]+\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b",
    },
    {
        "entity_type": "DATE_GENERIC",
        "category": "PII",
        "base_confidence": 0.50,
        "description": "Generic date — low confidence, needs Claude review",
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
        "description": "Bank account number",
        "pattern": r"\b(?:account\s*(?:number|#|no\.?)?[\s:]*)?(\d{8,17})\b",
    },
    {
        "entity_type": "ROUTING_NUMBER",
        "category": "PII",
        "base_confidence": 0.88,
        "description": "US ABA routing number",
        "pattern": r"\b[0123]\d{8}\b",
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

    # PHI — Medical
    {
        "entity_type": "NPI",
        "category": "PHI",
        "base_confidence": 0.90,
        "description": "National Provider Identifier",
        "pattern": r"\b(?:NPI|national\s+provider)[\s:#]*\d{10}\b",
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
        "pattern": r"\b[A-Z]{2}\d{7}\b",
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
        "pattern": r"\b(?:metformin|lisinopril|atorvastatin|levothyroxine|omeprazole|amlodipine|metoprolol|albuterol|gabapentin|sertraline|fluoxetine|amoxicillin|ibuprofen|warfarin)\b",
    },
    {
        "entity_type": "HOSPITAL_KEYWORD",
        "category": "PHI",
        "base_confidence": 0.60,
        "description": "Hospital/clinic keyword — needs Claude review",
        "pattern": r"\b(?:hospital|medical\s+center|clinic|healthcare|health\s+system|urgent\s+care|emergency\s+room|ER|ICU|OR)\b",
    },
]