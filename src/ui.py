"""
DataSentry v2 — Streamlit UI (compatible with Streamlit 1.12.0)
"""

import os
import requests
import streamlit as st
import pandas as pd

API_BASE = os.environ.get("DATASENTRY_API_URL", "http://localhost:8000")

st.set_page_config(page_title="DataSentry v2", page_icon="🔍")
st.title("DataSentry v2")
st.caption("Hybrid PII/PHI Detection — 4-layer architecture with LLM arbitration")

tab = st.radio("", ["Detect", "Audit Trail", "Search"], horizontal=True)

# ── DETECT ─────────────────────────────────────────────────────
if tab == "Detect":
    samples = {
        "Sample 1 — Patient record": (
            "Patient John Smith, DOB: 03/15/1978, SSN 432-56-7890 was admitted to "
            "City Medical Center. MRN: MRN-2024-00142. Diagnosis: E11.9 (Type 2 Diabetes). "
            "Prescribed metformin 500mg. Contact: jsmith@email.com | (555) 867-5309"
        ),
        "Sample 2 — Financial": (
            "Account holder: Sarah Johnson, account number 8834291055, "
            "routing 021000021. Credit card: 4532015112830366. "
            "Address: 742 Evergreen Terrace, Springfield, IL 62701."
        ),
        "Sample 3 — Ambiguous": (
            "The patient was seen at the clinic in January. "
            "Her doctor noted concerning values. She takes daily medication. "
            "Insurance member id: MBR-2024-99182."
        ),
        "Custom": "",
    }

    choice = st.selectbox("Load a sample:", list(samples.keys()))
    text_input = st.text_area("Text to scan", value=samples[choice], height=180)
    source_label = st.text_input("Source label", value="streamlit_ui")
    run_btn = st.button("Run Detection")

    if run_btn and text_input.strip():
        with st.spinner("Running 4-layer detection..."):
            try:
                resp = requests.post(
                    f"{API_BASE}/detect",
                    json={"text": text_input, "source_label": source_label},
                    timeout=60,
                )
                resp.raise_for_status()
                data = resp.json()

                st.success(f"Done in {data['processing_ms']}ms")

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("PII", data["total_pii"])
                col2.metric("PHI", data["total_phi"])
                col3.metric("Entities", data["entity_count"])
                col4.metric("Layers", len(data["layers_used"]))

                st.caption(f"Run ID: `{data['run_id'][:12]}...` | Layers: {', '.join(data['layers_used'])}")

                if data["entities"]:
                    st.subheader("Detected entities")
                    for ent in data["entities"]:
                        conf = ent["confidence"]
                        icon = "🟢" if conf >= 0.85 else "🟡" if conf >= 0.75 else "🔴"
                        claude_note = " *(Claude reviewed)*" if ent["escalated"] else ""
                        with st.expander(
                            f"{icon} {ent['entity_type']} — {ent['text'][:30]} "
                            f"({ent['category']}, {conf:.0%}){claude_note}"
                        ):
                            st.write(f"**Layer:** {ent['detection_layer']}")
                            st.write(f"**Confidence:** {conf:.4f}")
                            st.write(f"**Position:** chars {ent['start']}–{ent['end']}")
                            st.write(f"**Rationale:** {ent['rationale']}")
                            if ent["claude_override"]:
                                st.info("Claude revised this classification.")
                else:
                    st.success("No PII/PHI detected.")

                # Annotated text
                st.subheader("Annotated text")
                highlighted = text_input
                for ent in sorted(data["entities"], key=lambda e: e["start"], reverse=True):
                    color = "#ffcccc" if ent["category"] == "PHI" else "#ffe0b2"
                    tag = (
                        f'<mark style="background:{color};padding:1px 4px;'
                        f'border-radius:3px;font-size:13px">'
                        f'{highlighted[ent["start"]:ent["end"]]}'
                        f'<sup style="font-size:9px">[{ent["entity_type"]}]</sup></mark>'
                    )
                    highlighted = highlighted[:ent["start"]] + tag + highlighted[ent["end"]:]
                st.markdown(highlighted, unsafe_allow_html=True)
                st.caption("🔴 PHI   🟠 PII")

            except requests.exceptions.ConnectionError:
                st.error(f"Cannot connect to API at {API_BASE}. Is the server running?")
            except Exception as e:
                st.error(f"Error: {e}")
    elif run_btn:
        st.warning("Enter some text first.")

# ── AUDIT TRAIL ────────────────────────────────────────────────
elif tab == "Audit Trail":
    st.subheader("Audit trail")

    if st.button("Refresh"):
        st.experimental_rerun()

    try:
        stats = requests.get(f"{API_BASE}/audit/stats", timeout=10).json()
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Total runs", stats["total_runs"])
        col2.metric("PII found", stats["total_pii_found"])
        col3.metric("PHI found", stats["total_phi_found"])
        col4.metric("Claude escalations", stats["escalated_to_claude"])
        col5.metric("Avg ms", stats["avg_processing_ms"])
    except Exception as e:
        st.error(f"Could not load stats: {e}")

    st.markdown("---")

    try:
        runs = requests.get(f"{API_BASE}/audit/runs?limit=100", timeout=10).json()
        if runs:
            df = pd.DataFrame(runs)
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
            df = df[["run_id", "source_label", "timestamp", "total_pii", "total_phi", "entity_count", "processing_ms"]]
            df.columns = ["Run ID", "Source", "Time", "PII", "PHI", "Entities", "ms"]
            df["Run ID"] = df["Run ID"].str[:12] + "..."
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No runs yet. Run a detection first.")
    except Exception as e:
        st.error(f"Could not load runs: {e}")

# ── SEARCH ─────────────────────────────────────────────────────
elif tab == "Search":
    st.subheader("Search entities")

    search_type = st.selectbox("Entity type", [
        "", "SSN", "EMAIL", "PHONE_US", "CREDIT_CARD", "PERSON_NAME",
        "DATE_OF_BIRTH", "MRN", "ICD_CODE", "NPI", "MEDICATION", "IP_ADDRESS"
    ])
    search_cat = st.selectbox("Category", ["", "PII", "PHI"])
    min_conf = st.slider("Min confidence", 0.0, 1.0, 0.0, 0.05)

    if st.button("Search"):
        try:
            params = {"min_confidence": min_conf, "limit": 200}
            if search_type:
                params["entity_type"] = search_type
            if search_cat:
                params["category"] = search_cat
            results = requests.get(
                f"{API_BASE}/audit/search", params=params, timeout=10
            ).json()
            if results:
                df = pd.DataFrame(results)
                df = df[["entity_text", "entity_type", "category",
                          "confidence", "detection_layer", "escalated", "rationale"]]
                df["confidence"] = df["confidence"].round(3)
                st.dataframe(df, use_container_width=True)
                st.caption(f"{len(results)} entities found")
            else:
                st.info("No entities found.")
        except Exception as e:
            st.error(f"Search failed: {e}")