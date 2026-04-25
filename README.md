---
title: DataSentry v2
emoji: 🔍
colorFrom: blue
colorTo: green
sdk: gradio
sdk_version: 4.7.1
app_file: app.py
pinned: false
python_version: "3.11"
---

# DataSentry v2

Hybrid PII/PHI detection engine with 4-layer architecture and full audit trail.

## Live Demo
🔗 https://sriDevelops-datasentry.hf.space

## Architecture
- Layer 1: Regex patterns (SSN, email, credit card, ICD codes)
- Layer 2: spaCy NER (person names, locations, facilities)  
- Layer 3: Claude LLM arbitration (ambiguous entities below 0.75 confidence)
- Layer 4: SQLite audit trail (every decision logged)

## Stack
Python 3.11 · spaCy 3.7.4 · Claude API · FastAPI · Gradio

## Links
- GitHub: https://github.com/sri-25/datasentry
- Live Demo: https://sriDevelops-datasentry.hf.space
- Author: https://linkedin.com/in/srijan24
