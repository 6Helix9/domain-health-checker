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
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- 🚀 ULTRA PREMIUM UI THEME INJECTION (WOW EFFECT) 🚀 ---
st.markdown("""
<style>
    /* Premium Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;700&display=swap');
    
    /* Global Background & Typography */
    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Plus Jakarta Sans', sans-serif;
        background: #050505;
        background-image: 
            radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
            radial-gradient(at 100% 100%, rgba(217, 70, 239, 0.15) 0px, transparent 50%);
        background-attachment: fixed;
        color: #e2e8f0;
    }
    
    /* Hide default Streamlit overheads */
    #MainMenu, footer, header {visibility: hidden;}
    
    /* Ultra Modern Text Area (Glassmorphism + Neon Focus) */
    div[data-testid="stTextArea"] textarea {
        background: rgba(255, 255, 255, 0.02) !important;
        backdrop-filter: blur(10px) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 16px !important;
        color: #34d399 !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 15px !important;
        padding: 16px !important;
        box-shadow: inset 0 4px 20px rgba(0, 0, 0, 0.5) !important;
        transition: all 0.3s ease !important;
    }
    div[data-testid="stTextArea"] textarea:focus {
        border-color: #8b5cf6 !important;
        box-shadow: 0 0 25px rgba(139, 92, 246, 0.3), inset 0 4px 20px rgba(0, 0, 0, 0.5) !important;
    }

    /* Primary Action Button - Animated Gradient Glow */
    button[kind="primary"] {
        background: linear-gradient(45deg, #4f46e5, #8b5cf6, #ec4899) !important;
        background-size: 200% 200% !important;
        animation: gradientGlow 4s ease infinite !important;
        border: none !important;
        border-radius: 12px !important;
        padding: 14px 32px !important;
        color: white !important;
        font-weight: 800 !important;
        letter-spacing: 1.5px !important;
        text-transform: uppercase !important;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4) !important;
    }
    @keyframes gradientGlow {
        0% {background-position: 0% 50%;}
        50% {background-position: 100% 50%;}
        100% {background-position: 0% 50%;}
    }
    button[kind="primary"]:hover {
        transform: translateY(-3px) scale(1.02) !important;
        box-shadow: 0 12px 30px rgba(139, 92, 246, 0.6) !important;
    }

    /* Warning Card - Red Glassmorphism */
    .warning-card {
        background: rgba(239, 68, 68, 0.03);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(239, 68, 68, 0.15);
        border-top: 4px solid #ef4444;
        border-radius: 16px;
        padding: 32px;
        box-shadow: 0 20px 40px -15px rgba(239, 68, 68, 0.15);
        text-align: center;
        height: 100%;
        position: relative;
        overflow: hidden;
    }
    .warning-card::before {
        content: '';
        position: absolute;
        top: 0; left: -100%; width: 50%; height: 100%;
        background: linear-gradient(to right, transparent, rgba(239, 68, 68, 0.1), transparent);
        transform: skewX(-20deg);
        animation: shine 4s infinite;
    }
    @keyframes shine {
        0% {left: -100%;}
        20% {left: 200%;}
        100% {left: 200%;}
    }
    .warning-btn {
        display: inline-block;
        background: rgba(239, 68, 68, 0.1);
        color: #fca5a5 !important;
        border: 1px solid rgba(239, 68, 68, 0.4);
        font-weight: 700;
        font-size: 14px;
        padding: 12px 28px;
        border-radius: 10px;
        text-decoration: none !important;
        transition: all 0.3s ease;
        letter-spacing: 1px;
        margin-top: 16px;
        text-transform: uppercase;
    }
    .warning-btn:hover {
        background: #ef4444;
        color: white !important;
        box-shadow: 0 0 20px rgba(239, 68, 68, 0.6);
        transform: translateY(-2px);
    }
    
    /* Code block styling */
    stCodeBlock {
        border-radius: 12px !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
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
    
    reputation_clean = (
        not detected_bls and 
        "CLEAN" in gsb and 
        "CLEAN" in vt and 
        "CLEAN" in urlhaus
    )

    if reputation_clean and ssl_ok:
        final_status = "GOOD"
    elif reputation_clean and not ssl_ok:
        final_status = "NON-SSL"
    else:
        final_status = "BAD"

    return {
        "Domain": domain,
        "SSL Gateway": ssl_val,
        "DNS Blocklists": bl_summary,
        "Google Safe Browsing": gsb,
        "VirusTotal Intelligence": vt,
        "URLHaus Payload": urlhaus,
        "Status": final_status
    }

def style_df_rows(row):
    base_style = "background-color: rgba(255,255,255,0.02); border-bottom: 1px solid rgba(255,255,255,0.05); color: #e2e8f0; font-family: 'JetBrains Mono', monospace;"
    glow_style = "background-color: {bg}; border-bottom: 1px solid rgba(255,255,255,0.05); color: {color}; text-shadow: 0 0 15px {color}; font-weight: 800; text-align: center; font-size: 15px; font-family: 'Plus Jakarta Sans', sans-serif; letter-spacing: 1px;"
    
    if row["Status"] == "GOOD":
        bg = "rgba(16, 185, 129, 0.05)"
        glow_color = "#10b981"
    elif row["Status"] == "NON-SSL":
        bg = "rgba(245, 158, 11, 0.05)"
        glow_color = "#f59e0b"
    else:
        bg = "rgba(239, 68, 68, 0.05)"
        glow_color = "#ef4444"
        
    styles = []
    for col in row.index:
        if col == "Status":
            styles.append(glow_style.format(bg=bg, color=glow_color))
        else:
            styles.append(base_style.format(bg=bg))
            
    return styles

# --- Master Layout Assembly ---

# Futuristic Header
st.markdown("""
<div style='text-align: center; margin-bottom: 40px; margin-top: 20px;'>
    <h1 style='font-weight: 800; font-size: 42px; background: linear-gradient(to right, #8b5cf6, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px;'>
        ⚡ Domain Checker ⚡
    </h1>
    <p style='color: #94a3b8; font-size: 16px; font-weight: 500; letter-spacing: 1px;'>
        SECURE THE CHAIN. GUARANTEE THE DROP.
    </p>
</div>
""", unsafe_allow_html=True)

GOOGLE_API_KEY = st.secrets.get("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_KEY", "")
SPAMHAUS_DQS_KEY = st.secrets.get("SPAMHAUS_DQS_KEY", "")

domains_input = st.text_area(
    "Target Domains Submissions",
    height=160,
    placeholder="Enter targets one per line (e.g., example.com)\n>_ waiting for input...",
    label_visibility="collapsed"
)

# Center the button using columns
col_btn1, col_btn2, col_btn3 = st.columns([1, 2, 1])
with col_btn2:
    run_check = st.button(" Run Deep Scan", type="primary", use_container_width=True)

if run_check:
    target_list = [d.strip() for d in domains_input.splitlines() if d.strip()]
    
    if not target_list:
        st.error("Submission queue empty. Please add at least one domain first.")
    else:
        st.markdown("<br>", unsafe_allow_html=True)
        scan_progress = st.progress(0, text="Establishing secure connections...")
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
                scan_progress.progress(completed / len(target_list), text=f"Scanning nodes: {completed}/{len(target_list)}")
        
        scan_progress.empty()
        df = pd.DataFrame(dataset)

        st.markdown("<h3 style='font-weight:700; margin-bottom:16px; color:#f8fafc;'>📡 Results</h3>", unsafe_allow_html=True)
        st.dataframe(
            df.style.apply(style_df_rows, axis=1), 
            use_container_width=True,
            hide_index=True,
            height=(len(df) * 40) + 40
        )

        st.markdown("<div style='margin-top: 40px;'></div>", unsafe_allow_html=True)
        
        # --- Side-by-Side Layout ---
        col1, col2 = st.columns([1, 1.2], gap="large")
        
        with col1:
            clean_assets = df[(df["Status"] == "GOOD") | (df["Status"] == "NON-SSL")]["Domain"].tolist()
            st.markdown("<h3 style='font-weight:700; margin-bottom:16px; color:#34d399;'>✅ Ready To Use</h3>", unsafe_allow_html=True)
            if clean_assets:
                st.code("\n".join(clean_assets), language="text")
            else:
                st.markdown("""
                <div style='background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); color:#fca5a5; padding: 16px 20px; border-radius:12px; font-weight: 500;'>
                    ⚠️ Zero clean domains identified in this batch.
                </div>
                """, unsafe_allow_html=True)

        with col2:
            st.markdown(
                """
                <div class="warning-card">
                    <div style="font-size: 36px; margin-bottom: 12px; line-height: 1;">⚠️</div>
                    <h3 style="color: #f87171; font-weight: 800; font-size: 18px; text-transform: uppercase; letter-spacing: 2px; margin: 0 0 16px 0;">
                        Critical Protocol
                    </h3>
                    <div style="color: #cbd5e1; font-size: 15px; line-height: 1.6; margin-bottom: 20px; text-align: center; font-weight: 400;">
                        <p style="margin: 0 0 16px 0;">
                            Every selected domain must be manually verified.<br>
                            Confirm zero listings on Spamhaus or major blacklists.
                        </p>
                        <div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 12px; padding: 12px; margin: 16px 0;">
                            <span style="color: #fbbf24; font-weight: 700; font-size: 12px; letter-spacing: 1px; display: block; margin-bottom: 4px;">💡 NON-SSL EXCEPTION</span>
                            <span style="color: #94a3b8; font-size: 13px;">NON-SSL domains with a clean reputation are acceptable for standard HTTP redirects/drops.</span>
                        </div>
                    </div>
                    <a href="https://wintelguy.com/url-blacklist-checker.pl" target="_blank" class="warning-btn">
                        🔗 Verify on WintelGuy
                    </a>
                </div>
                """,
                unsafe_allow_html=True,
            )

st.markdown(
    """
    <div style="text-align: center; margin-top: 60px; padding: 30px 0; border-top: 1px solid rgba(255,255,255,0.05);
                color: #64748b; font-size: 13px; letter-spacing: 1px; font-weight: 500;">
        ⚡ NO PLAN, JUST FLOW — <span style="color:#c084fc; font-weight:700;">VIBE CODED</span>
        BY <span style="color:#34d399; font-weight:700;">ASCENDED696</span>
    </div>
    """,
    unsafe_allow_html=True,
)
