"""
DataSentry v2 — Gradio UI for Hugging Face Spaces
Runs the full 4-layer detection pipeline inline — no separate API needed.
"""

import os
import gradio as gr
from dotenv import load_dotenv
load_dotenv()

from src.detector import DataSentryDetector

detector = DataSentryDetector(
    spacy_model="en_core_web_sm",
    audit_db="/tmp/datasentry_audit.db"
)

SAMPLES = {
    "Patient record": (
        "Patient John Smith, DOB: 03/15/1978, SSN 432-56-7890 was admitted to "
        "City Medical Center. MRN: MRN-2024-00142. Diagnosis: E11.9 (Type 2 Diabetes). "
        "Prescribed metformin 500mg. Contact: jsmith@email.com | (555) 867-5309"
    ),
    "Financial data": (
        "Account holder: Sarah Johnson, account number 8834291055, "
        "routing 021000021. Credit card: 4532015112830366. "
        "Address: 742 Evergreen Terrace, Springfield, IL 62701."
    ),
    "Ambiguous text": (
        "The patient was seen at the clinic in January. "
        "Her doctor noted concerning values. She takes daily medication. "
        "Insurance member id: MBR-2024-99182."
    ),
}


def detect(text, source_label):
    if not text.strip():
        return "Please enter some text.", "", ""

    result = detector.detect(text, source_label=source_label or "gradio_ui")

    # Build entity table
    if not result.entities:
        table = "No PII/PHI detected."
    else:
        rows = []
        for e in result.entities:
            claude = "Yes" if e.escalated else "No"
            rows.append(
                f"| {e.entity_type} | {e.text[:30]} | {e.category} | "
                f"{e.confidence:.2f} | {e.detection_layer} | {claude} |"
            )
        header = (
            "| Entity Type | Text | Category | Confidence | Layer | Claude? |\n"
            "|-------------|------|----------|-----------|-------|---------|"
        )
        table = header + "\n" + "\n".join(rows)

    # Build summary
    summary = (
        f"**PII found:** {result.total_pii}  |  "
        f"**PHI found:** {result.total_phi}  |  "
        f"**Processing:** {result.processing_ms}ms  |  "
        f"**Layers:** {', '.join(set(result.layers_used))}"
    )

    # Build annotated text
    highlighted = text
    for e in sorted(result.entities, key=lambda x: x.start, reverse=True):
        label = f"[{e.entity_type}]"
        highlighted = (
            highlighted[:e.start] +
            f"**{highlighted[e.start:e.end]}**{label}" +
            highlighted[e.end:]
        )

    return summary, table, highlighted


def load_sample(sample_name):
    return SAMPLES.get(sample_name, "")


with gr.Blocks(title="DataSentry v2") as demo:
    gr.Markdown("""
# DataSentry v2
**Hybrid PII/PHI Detection Engine** — 4-layer architecture: Regex → spaCy NER → Claude LLM → SQLite Audit

Built by [Srijan Gupta](https://linkedin.com/in/srijan24) · [GitHub](https://github.com/sri-25/datasentry)
    """)

    with gr.Row():
        with gr.Column(scale=2):
            sample_dropdown = gr.Dropdown(
                choices=list(SAMPLES.keys()),
                label="Load a sample",
                value=None
            )
            text_input = gr.Textbox(
                label="Text to scan",
                placeholder="Paste any text containing potential PII or PHI...",
                lines=6
            )
            source_label = gr.Textbox(
                label="Source label",
                value="gradio_ui",
                lines=1
            )
            detect_btn = gr.Button("Run Detection", variant="primary")

        with gr.Column(scale=3):
            summary_out = gr.Markdown(label="Summary")
            table_out = gr.Markdown(label="Detected Entities")
            annotated_out = gr.Markdown(label="Annotated Text")

    sample_dropdown.change(fn=load_sample, inputs=sample_dropdown, outputs=text_input)
    detect_btn.click(
        fn=detect,
        inputs=[text_input, source_label],
        outputs=[summary_out, table_out, annotated_out]
    )

    gr.Markdown("""
---
### Architecture
| Layer | Method | Confidence | Handles |
|-------|--------|-----------|---------|
| 1 | Regex patterns | 0.78–0.95 | SSN, email, credit card, ICD codes |
| 2 | spaCy NER | 0.50–0.70 | Person names, locations, facilities |
| 3 | Claude LLM | < 0.75 threshold | Medications, ambiguous dates, hospital keywords |
| 4 | SQLite audit | — | Every decision logged with full provenance |
    """)

demo.launch()
