# SIEM-Query-Generator

Purpose-built Natural Language to SIEM Query translator designed by and for Security Operations Centers (SOCs).

## Features
- Converts analyst natural-language hunting requests into SIEM query syntax.
- Applies embedded SOC guardrails in generated output:
  - Time range constrained to last 24 hours.
  - Service account suppression for `svc_*` identities.
  - Result-size caps to 100 events.
- Produces 3–4 follow-on investigative pivots for triage and deeper hunting.
- Supports KQL (Microsoft Sentinel), YARA-L (Google SecOps), Sigma, and Splunk SPL targets.

## Run locally
1. Install dependencies:
   ```bash
   pip install streamlit google-generativeai
   ```
2. Start the app:
   ```bash
   streamlit run app.py
   ```
3. Enter your Google Gemini API key in the sidebar and submit a hunting request.
