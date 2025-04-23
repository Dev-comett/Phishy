
import base64
import requests
import streamlit as st

# ─── Load API Keys from Streamlit Secrets ────────────────────────────────────────
VIRUS_TOTAL_API_KEY = st.secrets["VIRUS_TOTAL_API_KEY"]
SAFE_BROWSING_API_KEY = st.secrets["SAFE_BROWSING_API_KEY"]

# ─── Page Config  ────────────────────────────────────────
st.set_page_config(page_title="URL Safety Checker", layout="wide", initial_sidebar_state="collapsed")
st.markdown(
    """
    <style>
    body {
      background-color: #000000;
      color: #FFFFFF;
      font-family: 'Arial', sans-serif;
    }
    .stApp {
      max-width: 100%;
      margin: 0;
      padding: 1rem;
    }
    .stButton>button {
      background-color: #FF9900;
      color: #000000;
      border-radius: 4px;
      padding: 0.8rem 1.5rem;
      font-size: 1.1rem;
      font-weight: bold;
    }
    .stTextInput>div>div>input {
      background-color: #1a1a1a;
      color: #FFF;
      border: 2px solid #FF9900;
      border-radius: 4px;
      padding: 0.8rem;
      font-size: 1rem;
    }
    .stProgress > div > div {
      background-color: #FF9900 !important;
    }
    h1, h2, h3 {
      color: #FF9900;
    }
    .section-header {
      color: #FF9900;
      border-bottom: 2px solid #FF9900;
      padding-bottom: 8px;
      margin-bottom: 16px;
    }
    a {
      color: #FF9900;
    }
    .footer {
      text-align: center;
      padding: 20px 0;
      background-color: #000;
      color: #FF9900;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─── Utility Functions ────────────────────────────────────────────────────────────
def encode_url_for_vt(u: str) -> str:
    """Base64-encode the URL (VirusTotal requirement)."""
    return base64.urlsafe_b64encode(u.encode()).decode().strip("=")

def check_virus_total(u: str) -> dict:
    """Call VirusTotal and return parsed stats."""
    encoded = encode_url_for_vt(u)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"
    headers = {"x-apikey": VIRUS_TOTAL_API_KEY}
    resp = requests.get(endpoint, headers=headers)
    if resp.status_code != 200:
        st.error(f"VirusTotal Error {resp.status_code}")
        return {}
    data = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return data

def check_safe_browsing(u: str) -> bool:
    """Return True if Safe Browsing flags this URL as malicious."""
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "url-safety-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u}],
        },
    }
    resp = requests.post(endpoint, json=payload)
    if resp.status_code != 200:
        st.error(f"Safe Browsing Error {resp.status_code}")
        return False
    return bool(resp.json().get("matches"))

# ─── Initialize History ──────────────────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []

def save_history(url, result):
    st.session_state.history.append({"url": url, "result": result})

# ─── Main UI Logic ───────────────────────────────────────────────────────────────
st.title("🔍 URL Safety Checker")
st.write("Enter a URL below to check if it’s safe or malicious.")

user_url = st.text_input("🔗 URL to check")

# Report Section
st.markdown("[Report Malicious URL](https://forms.gle/5NyEQT9oizGEoYteA) to report suspicious links.")

if st.button("Run Check"):
    if not user_url:
        st.warning("Please enter a URL first.")
    else:
        progress = st.progress(0)
        st.info("Checking with VirusTotal...")
        vt_stats = check_virus_total(user_url)
        progress.progress(50)

        st.info("Checking with Google Safe Browsing...")
        sb_flagged = check_safe_browsing(user_url)
        progress.progress(100)

        st.markdown("---")
        # VirusTotal Summary
        if vt_stats:
            st.subheader("VirusTotal Analysis")
            st.write(f"• Harmless: **{vt_stats.get('harmless', 0)}**")
            st.write(f"• Malicious: **{vt_stats.get('malicious', 0)}**")
            st.write(f"• Suspicious: **{vt_stats.get('suspicious', 0)}**")
        else:
            st.write("No data from VirusTotal.")

        # Safe Browsing Summary
        st.subheader("Google Safe Browsing")
        if sb_flagged:
            st.write("• This URL **was flagged** as malicious by Google Safe Browsing.")
        else:
            st.write("• No threats detected by Google Safe Browsing.")

        # Final Conclusion
        is_bad = (vt_stats.get("malicious", 0) > 0) or sb_flagged
        if is_bad:
            st.error("🚨 Conclusion: This URL appears **MALICIOUS**. Proceed with extreme caution.")
        else:
            st.success("✅ Conclusion: This URL appears **SAFE**.")

        save_history(user_url, "MALICIOUS" if is_bad else "SAFE")
        progress.empty()

# ─── History Section at Bottom ──────────────────────────────────────────────────
if st.session_state.history:
    st.markdown("---")
    st.subheader("History")
    for record in st.session_state.history:
        st.write(f"URL: {record['url']} ➤ Result: {record['result']}")

# ─── Footer ─────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="footer">
        Made with 💓 by Im_Dev | 
        <a href="https://github.com/dev-comett" target="_blank">GitHub</a> | 
        <a href="https://linkedin.com/in/dev-ice" target="_blank">LinkedIn</a>
    </div>
    """,
    unsafe_allow_html=True,
)

