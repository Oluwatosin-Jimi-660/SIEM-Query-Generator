import json

import google.generativeai as genai
import streamlit as st

# -----------------------------------------
# UI/UX Configuration
# -----------------------------------------
st.set_page_config(
    page_title="SIEM Query Generator | NL to Query",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for a cleaner, SOC-focused UI
st.markdown(
    """
    <style>
    .stTextArea textarea { font-family: monospace; font-size: 14px; }
    .recommendation-box {
        background-color: #1e1e2e;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #6366f1;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------
# AI Initialization & Prompt Engineering
# -----------------------------------------
def initialize_ai(api_key: str) -> genai.GenerativeModel:
    genai.configure(api_key=api_key)

    preferred_model = "gemini-1.5-flash"
    try:
        # Prefer a fast default, but fall back to any available text-generation model.
        return genai.GenerativeModel(preferred_model)
    except Exception:
        available_models = [
            model.name
            for model in genai.list_models()
            if "generateContent" in getattr(model, "supported_generation_methods", [])
        ]
        if not available_models:
            raise
        return genai.GenerativeModel(available_models[0])


def generate_siem_data(model: genai.GenerativeModel, nl_input: str, language: str) -> dict:
    system_prompt = f"""
    You are a Senior Security Detection Engineer. Your stack focus is Microsoft Entra ID, Azure, AWS, and Google SecOps.
    Translate the following Natural Language threat hunting request into a highly optimized {language} query.

    CRITICAL SOC GUARDRAILS (YOU MUST INJECT THESE INTO THE QUERY):
    1. Time scoping: Restrict the search to the last 24 hours.
    2. Exclude service accounts: Filter out users/accounts starting with "svc_".
    3. Performance limit: Limit the output to 100 results (e.g., `| take 100`, `| head 100`, etc.).

    INVESTIGATIVE RECOMMENDATIONS:
    Provide 3 to 4 logical next-step investigative search terms, pivots, or logic steps based on the context of the user's input.
    (e.g., if checking IPs, suggest "Auth Success vs Failure", "Device IDs").

    OUTPUT FORMAT:
    You must return a valid JSON object with EXACTLY two keys: "query" and "recommendations".
    "query" must be a string containing the raw code.
    "recommendations" must be a list of 3-4 strings.
    Do not wrap the JSON in markdown code blocks. Just return the raw JSON string.
    """

    response = model.generate_content(f"{system_prompt}\n\nUser Request: {nl_input}")

    try:
        # Strip potential markdown formatting if the model disobeys.
        clean_text = (
            response.text.strip().removeprefix("```json").removesuffix("```").strip()
        )
        return json.loads(clean_text)
    except json.JSONDecodeError:
        return {
            "query": "-- Error parsing AI response. Please try again.",
            "recommendations": [],
        }


# -----------------------------------------
# Application Layout
# -----------------------------------------
st.title("🛡️ SIEM Query Generator")
st.markdown("Translate Natural Language to Guardrailed SIEM Queries.")

# Sidebar Controls
with st.sidebar:
    st.header("⚙️ Configuration")
    api_key = st.text_input(
        "Google Gemini API Key",
        type="password",
        help="Required to power the AI engine.",
    )

    st.divider()

    st.header("🎯 Target Environment")
    siem_language = st.selectbox(
        "Select SIEM / Query Language",
        ["KQL (Microsoft Sentinel)", "YARA-L (Google SecOps)", "Sigma", "Splunk SPL"],
    )

    st.markdown(
        """
    **Active SOC Guardrails:**
    * ⏱️ `Time: Last 24h`
    * 👤 `Exclude: svc_*`
    * 🛑 `Limit: 100 events`
    """
    )

# Main Content Area
nl_input = st.text_area(
    "Describe the threat or activity you are hunting for:",
    placeholder="e.g., Show me users activating PIM and then creating a new Global Admin...",
    height=100,
)

col1, _ = st.columns([3, 1])

with col1:
    generate_btn = st.button("Generate Query", type="primary", use_container_width=True)

if generate_btn:
    if not api_key:
        st.error("Please provide a Gemini API Key in the sidebar.")
    elif not nl_input:
        st.warning("Please describe a threat to generate a query.")
    else:
        with st.spinner("Compiling query and generating recommendations..."):
            model = initialize_ai(api_key)
            result = generate_siem_data(model, nl_input, siem_language)

            st.subheader(f"Generated {siem_language} Query")
            st.code(result.get("query", "Error generating query."), language="sql")

            # Recommendations Panel
            st.subheader("🔍 Investigative Recommendations")
            recs = result.get("recommendations", [])
            if recs:
                for rec in recs:
                    st.markdown(
                        f'<div class="recommendation-box" style="margin-bottom: 10px;">'
                        f"💡 <strong>Pivot:</strong> {rec}</div>",
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No recommendations generated.")
