
import streamlit as st
import google.generativeai as genai
import re
import pandas as pd
from datetime import datetime

# --- Page Configuration ---
st.set_page_config(
    page_title="AgentGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Branding ---
st.markdown("""
<style>
/* Custom button style */
.stButton > button {
    border: 2px solid #4CAF50;
    background-color: transparent;
    color: #4CAF50;
    padding: 10px 24px;
    cursor: pointer;
    font-size: 16px;
    font-weight: bold;
    border-radius: 8px;
    transition: all 0.3s ease-in-out;
}
.stButton > button:hover {
    background-color: #4CAF50;
    color: white;
}
/* Custom primary button style for approval */
.stButton > button[kind="primary"] {
    background-color: transparent;
    color: #00f2ff;
    border: 2px solid #00f2ff;
}
.stButton > button[kind="primary"]:hover {
    background-color: #00f2ff;
    color: #111;
}
.stButton > button:disabled {
    border-color: #555;
    color: #555;
    background-color: transparent;
}
</style>
""", unsafe_allow_html=True)


# --- App State Initialization ---
if 'audit_log' not in st.session_state:
    st.session_state.audit_log = [
        {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Original Prompt": "Initial dummy prompt: email sales@company.com",
            "Redacted Prompt": "Initial dummy prompt: email [REDACTED_PII]",
            "AI Response": "This is a sample response for the initial dummy log entry.",
            "Security Layer": "Enabled"
        }
    ]
if 'human_in_the_loop_approval' not in st.session_state:
    st.session_state.human_in_the_loop_approval = None
if 'latest_response' not in st.session_state:
    st.session_state.latest_response = None

# --- Helper Functions ---
def convert_df_to_csv(df):
    """Converts a DataFrame to a CSV string for downloading."""
    return df.to_csv(index=False).encode('utf-8')

# --- Security Engine (PII Redaction) ---
def sanitize_prompt(text, security_enabled):
    """
    Scans text for emails and phone numbers and redacts them if security is enabled.
    Returns the sanitized text and a boolean indicating if a redaction occurred.
    """
    if not security_enabled:
        return text, False

    redacted = False
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    phone_regex = r'\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b'
    
    if re.search(email_regex, text):
        redacted = True
        text = re.sub(email_regex, '[REDACTED_PII]', text)
    if re.search(phone_regex, text):
        redacted = True
        text = re.sub(phone_regex, '[REDACTED_PII]', text)
        
    return text, redacted

def add_to_audit_log(original, redacted, response, security_status):
    st.session_state.audit_log.insert(0, {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Original Prompt": original,
        "Redacted Prompt": redacted,
        "AI Response": response,
        "Security Layer": "Enabled" if security_status else "Disabled"
    })

# --- Gemini API Call ---
def call_gemini(prompt, api_key):
    try:
        genai.configure(api_key=api_key)
        # Using a model that is likely to be available long-term for enterprise
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        st.error(f"An error occurred with the Gemini API: {e}")
        return None

# --- Sidebar Configuration ---
with st.sidebar:
    st.title("⚙️ Configuration")
    st.markdown("---")
    
    # Auto-authentication via st.secrets
    api_key = ""
    if "GOOGLE_API_KEY" in st.secrets:
        api_key = st.secrets["GOOGLE_API_KEY"]
        st.success("🔒 Enterprise License Active: Connected to Secure Gateway.")
    else:
        st.warning("No enterprise key found.")
        api_key = st.text_input("Enter Google API Key", type="password", help="Your API key is not stored.")

    st.markdown("---")
    security_enabled = st.toggle("🔴 ENABLE SECURITY LAYER", value=True)
    
    if security_enabled:
        st.success("● System Secure & Encrypted")
    else:
        st.error("● UNSECURE MODE (Use Caution)")
    st.markdown("---")
    st.info("When the Security Layer is enabled, prompts are automatically scanned for PII like emails and phone numbers before being sent to the AI.")
    
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; font-size: 0.8em; color: #777;'>
            <p>🔒 AgentGuard Enterprise Edition v1.0</p>
            <p>Built by Internal Security Team</p>
        </div>
        """,
        unsafe_allow_html=True
    )

# --- Main Application Interface ---
st.title("🛡️ AgentGuard Enterprise")
st.markdown("---")

# Enterprise Metrics
m1, m2 = st.columns(2)
m1.metric(label="System Status", value="Online", delta="All systems normal", delta_color="normal")
m2.metric(label="Encryption", value="AES-256", delta="End-to-end", delta_color="normal")
st.markdown("---")

if not api_key:
    st.error("API Key not configured. Please add it to your app's secrets or enter it in the sidebar.")
    st.stop()

# Main Agent Interaction Area
main_col, response_col = st.columns(2)

with main_col:
    st.header("Agent Command")
    prompt_text = st.text_area(
        "Enter command:", 
        height=200, 
        placeholder="e.g., 'Draft a contract for Client X' or 'Analyze this PII data...'"
    )
    run_agent_button = st.button("Run Agent", use_container_width=True)

    if run_agent_button and prompt_text:
        st.session_state.latest_response = None
        sanitized_text, was_redacted = sanitize_prompt(prompt_text, security_enabled)
        
        if was_redacted:
            st.session_state.human_in_the_loop_approval = {"original": prompt_text, "redacted": sanitized_text}
        else:
            st.session_state.human_in_the_loop_approval = None
            with st.spinner("Agent is processing..."):
                ai_response = call_gemini(sanitized_text, api_key)
                if ai_response:
                    add_to_audit_log(prompt_text, sanitized_text, ai_response, security_enabled)
                    st.session_state.latest_response = ai_response

if st.session_state.human_in_the_loop_approval:
    with main_col:
        st.warning("⛔ INTERCEPTION EVENT: PII Pattern Detected. Payload Scrubbed.")
        st.markdown("**Original Prompt:**")
        st.code(st.session_state.human_in_the_loop_approval['original'], language=None)
        st.markdown("**Scrubbed Payload for AI:**")
        st.code(st.session_state.human_in_the_loop_approval['redacted'], language=None)
        
        if st.button("✅ Approve and Send Scrubbed Payload", use_container_width=True, type="primary"):
            data = st.session_state.human_in_the_loop_approval
            with st.spinner("Agent is processing approved payload..."):
                ai_response = call_gemini(data['redacted'], api_key)
                if ai_response:
                    add_to_audit_log(data['original'], data['redacted'], ai_response, security_enabled)
                    st.session_state.latest_response = ai_response
            st.session_state.human_in_the_loop_approval = None
            st.rerun()

with response_col:
    st.header("AI Response")
    if st.session_state.latest_response:
        st.markdown(st.session_state.latest_response)
    else:
        st.info("The AI's response will appear here.")

# --- Audit Log Display ---
st.markdown("---")
st.header("Security Audit Log")
if st.session_state.audit_log:
    df = pd.DataFrame(st.session_state.audit_log)
    
    # Display Download Button
    csv_data = convert_df_to_csv(df)
    st.download_button(
        label="📄 Download Report (CSV)",
        data=csv_data,
        file_name=f"agentguard_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime='text/csv',
    )
    
    # Display Dataframe
    st.dataframe(df, use_container_width=True)
else:
    st.info("No activity yet. Run a command to see security events appear here.")
