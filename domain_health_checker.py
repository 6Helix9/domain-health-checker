import streamlit as st
import dns.resolver
import socket
import concurrent.futures
import ssl
import pandas as pd
import requests
from datetime import datetime

# --- Page Configuration ---
st.set_page_config(
    page_title="Expanded Redirect Domain Checker",
    page_icon="🔗",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- High-End Custom UI Theme Injection ---
st.markdown("""
<style>
    /* Global App Overrides */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Inter', sans-serif;
        background-color: #0d0f12;
        color: #f3f4f6;
    }
    
    /* Hide default Streamlit overheads cleanly */
    #MainMenu, footer, header {visibility: hidden;}
    
    /* Modern Input Form Styling */
    div[data-testid="stTextArea"] textarea {
        background-color: #161a1f !important;
        border: 1px solid #2d3748 !important;
        border-radius: 10px !important;
        color: #f3f4f6 !important;
        font-family: 'Fira Code', monospace !important;
        font-size: 14px !important;
        padding: 14px !important;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 1px #6366f1 !important;
    }

    /* Primary Action Button Refinement */
    button[kind="primary"] {
        background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%) !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 12px 28px !important;
        font-weight: 600 !important;
        letter-spacing: 0.3px !important;
        transition: all 0.2s ease-in-out !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.25) !important;
    }
    button[kind="primary"]:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4) !important;
    }

    /* Executive KPI Dashboard Cards */
    .kpi-container {
        display: flex;
        gap: 16px;
        margin-bottom: 24px;
    }
    .kpi-card {
        flex: 1;
        background-color: #161a1f;
        border: 1px solid #232932;
        border-radius: 12px;
        padding: 20px;
        text-align: left;
    }
    .kpi-label {
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: #9ca3af;
        margin-bottom: 6px;
        font-weight: 600;
    }
    .kpi-value {
        font-size: 28px;
        font-weight: 700;
        color: #ffffff;
    }
</style>
""", unsafe_allow_html=True)

# --- Configuration & Core Functions ---

def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert["notAfter"]
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.now()).days
                if days_left <= 0:
                    return "Expired", False
                return f"{days_left} days left", days_left > 7
    except Exception:
        return "No SSL Detected", False

def check_dnsbl(domain, zone, friendly_name):
    try:
        query = f"{domain}.{zone}"
        dns.resolver.resolve(query, "A")
        return friendly_name
    except Exception:
        return None

def check_google_safe_browsing(domain, api_key):
    if not api_key:
        return "Missing Credentials"
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "reputation-suite", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}"}, {"url": f"https://{domain}"}]
        }
    }
    try:
        response = requests.post(url, json=payload, timeout=4)
        if response.status_code == 200 and response.json():
            return "❌ FLAGGED"
        return "🟢 CLEAN"
    except Exception:
        return "API Timeout"

def check_virustotal(domain, api_key):
    if not api_key:
        return "Missing Credentials"
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=4)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            phishing = stats.get("phishing", 0)
            total_hits = malicious + phishing
            if total_hits > 0:
                return f"❌ FLAGGED ({total_hits} Engines)"
        return "🟢 CLEAN"
    except Exception:
        return "API Timeout"

def check_urlhaus(domain):
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    try:
        response = requests.post(url, data={"host": domain}, timeout=4)
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok" and data.get("blacklisted") == "yes":
                return "❌ FLAGGED"
        return "🟢 CLEAN"
    except Exception:
        return "API Timeout"

def analyze_domain(domain, google_key, vt_key, spamhaus_key):
    domain = domain.strip().lower()
    if not domain:
        return None
    
    try:
        socket.gethostbyname(domain)
    except Exception:
        return {
            "Domain": domain, "SSL Gateway": "⚠️ Connection Failed", "DNS Blocklists": "🔴 UNRESOLVABLE",
            "Google Safe Browsing": "—", "VirusTotal Intelligence": "—", "URLHaus Payload": "—",
            "Status": "BAD"
        }

    ssl_val, ssl_ok = check_ssl_expiry(domain)
    
    # Live DNSBL Matrix Execution
    detected_bls = []
    surbl = check_dnsbl(domain, "multi.surbl.org", "SURBL")
    sorbs = check_dnsbl(domain, "uribl.rhsbl.sorbs.net", "SORBS")
    
    if surbl: detected_bls.append(surbl)
    if sorbs: detected_bls.append(sorbs)
    
    if spamhaus_key:
        spamhaus = check_dnsbl(f"{domain}.{spamhaus_key}", "dbl.spamhaus.org", "Spamhaus DBL")
        if spamhaus: detected_bls.append(spamhaus)
    else:
        spamhaus = check_dnsbl(domain, "dbl.spamhaus.org", "Spamhaus DBL")
        if spamhaus: detected_bls.append(spamhaus)

    gsb = check_google_safe_browsing(domain, google_key)
    vt = check_virustotal(domain, vt_key)
    urlhaus = check_urlhaus(domain)
    
    bl_summary = f"❌ LISTED ({', '.join(detected_bls)})" if detected_bls else "🟢 CLEAN"
    
    is_clean = (
        ssl_ok and 
        not detected_bls and 
        "CLEAN" in gsb and 
        "CLEAN" in vt and 
        "CLEAN" in urlhaus
    )

    return {
        "Domain": domain,
        "SSL Gateway": ssl_val,
        "DNS Blocklists": bl_summary,
        "Google Safe Browsing": gsb,
        "VirusTotal Intelligence": vt,
        "URLHaus Payload": urlhaus,
        "Status": "GOOD" if is_clean else "BAD"
    }

def style_df_rows(row):
    # Professional subtle background styling for maximum readability
    if row["Status"] == "GOOD":
        return ["background-color: rgba(16, 185, 129, 0.08); color: #e1e7ef; border-bottom: 1px solid #1f2937;"] * len(row)
    else:
        return ["background-color: rgba(239, 68, 68, 0.06); color: #e1e7ef; border-bottom: 1px solid #1f2937;"] * len(row)

# --- Master Layout Assembly ---

# Header Section (Reverted to your original title and caption)
st.markdown("<h2 style='margin-bottom:0px; font-weight:700;'>🔗 Expanded Redirect Domain Checker</h2>", unsafe_allow_html=True)
st.markdown("<p style='color:#9ca3af; font-size:14px; margin-bottom:32px;'>Checks SSL expiration and maps domains against multi-source threat intelligence platforms.</p>", unsafe_allow_html=True)

# Secure Key Extraction
GOOGLE_API_KEY = st.secrets.get("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_KEY", "")
SPAMHAUS_DQS_KEY = st.secrets.get("SPAMHAUS_DQS_KEY", "")

# Input Field Configuration
domains_input = st.text_area(
    "Target Domains Submissions",
    height=160,
    placeholder="Enter targets one per line (e.g., example.com)",
    label_visibility="collapsed"
)

if st.button("Run Comprehensive Check", type="primary"):
    target_list = [d.strip() for d in domains_input.splitlines() if d.strip()]
    
    if not target_list:
        st.error("Submission queue empty. Please add at least one domain first.")
    else:
        # Dynamic Scanning UI Elements
        scan_progress = st.progress(0, text="Initializing scanning...")
        dataset = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as worker_pool:
            future_to_domain = {
                worker_pool.submit(analyze_domain, d, GOOGLE_API_KEY, VIRUSTOTAL_API_KEY, SPAMHAUS_DQS_KEY): d 
                for d in target_list
            }
            completed = 0
            for future in concurrent.futures.as_completed(future_to_domain):
                execution_payload = future.result()
                if execution_payload:
                    dataset.append(execution_payload)
                completed += 1
                scan_progress.progress(completed / len(target_list), text=f"Checked {completed}/{len(target_list)}")
        
        scan_progress.empty()
        df = pd.DataFrame(dataset)

        # Calculated State Parameters
        total_count = len(df)
        clean_count = len(df[df["Status"] == "GOOD"])
        compromised_count = total_count - clean_count

        # KPI Dashboard Layout Matrix Injection
        st.markdown(f"""
        <div class="kpi-container">
            <div class="kpi-card">
                <div class="kpi-label">Total Evaluated</div>
                <div class="kpi-value">{total_count}</div>
            </div>
            <div class="kpi-card" style="border-left: 3px solid #10b981;">
                <div class="kpi-label" style="color:#10b981;">Verified Clean</div>
                <div class="kpi-value" style="color:#34d399;">{clean_count}</div>
            </div>
            <div class="kpi-card" style="border-left: 3px solid #ef4444;">
                <div class="kpi-label" style="color:#ef4444;">Domains Flagged</div>
                <div class="kpi-value" style="color:#f87171;">{compromised_count}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # System Output Matrix Display
        st.markdown("<h4 style='font-weight:600; margin-bottom:12px;'>Analysis Results</h4>", unsafe_allow_html=True)
        st.dataframe(
            df.style.apply(style_df_rows, axis=1), 
            use_container_width=True,
            hide_index=True
        )

        # Actionable Target Outputs Separator
        clean_assets = df[df["Status"] == "GOOD"]["Domain"].tolist()
        st.markdown("<h4 style='font-weight:600; margin-top:28px; margin-bottom:12px;'>✅ Clean / Verified Domains</h4>", unsafe_allow_html=True)
        if clean_assets:
            st.code("\n".join(clean_assets), language="text")
        else:
            st.markdown("<div style='background-color:#1c1415; border: 1px solid #3b2326; color:#f87171; padding: 12px 16px; border-radius:8px; font-size:14px;'>⚠️ No completely clean domains identified in this batch.</div>", unsafe_allow_html=True)

        # --- Your Custom Warning Message Box (Completely Restored) ---
        st.markdown(
            """
            <div style="background-color:#2b1414; border-left: 4px solid #ff4d4d;
                        border-radius: 8px; padding: 16px 20px; margin-top: 24px;">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                    <span style="font-size:20px;">⚠️</span>
                    <span style="color:#ff6b6b; font-weight:700; font-size:16px;">
                        Before you launch any drops
                    </span>
                </div><br><br>
               <p style="color:#e6e6e6; font-size:14px; line-height:1.6; margin:0 0 14px 0;">
    Every selected domain must be manually double-checked before use.<br>
    Confirm that it is not listed on Spamhaus or any other blacklist.<br>
    Prefer to use domains that come back clean.<br>
    Do not launch on a domain that is flagged.<br>
</p>
                <a href="https://multirbl.valli.org/lookup" target="_blank"
                   style="display:inline-block; background-color:#ff4d4d; color:#1a0000;
                          font-weight:700; font-size:14px; padding:8px 16px;
                          border-radius:6px; text-decoration:none;">
                    🔗 Check domain on multirbl.valli.org
                </a>
            </div>
            """,
            unsafe_allow_html=True,
        )

# Signature Footer Node
st.markdown(
    """
    <div style="text-align: center; margin-top: 70px; padding: 24px 0; border-top: 1px solid #1f2937;
                color: #4b5563; font-size: 13px; letter-spacing: 0.5px;">
        ⚡ No plan, just flow — <span style="color:#a78bfa; font-weight:600;">vibe coded</span>
        by <span style="color:#34d399; font-weight:600;">Ascended696</span>
    </div>
    """,
    unsafe_allow_html=True,
)
