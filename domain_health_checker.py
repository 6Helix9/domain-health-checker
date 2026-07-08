import streamlit as st
import dns.resolver
import socket
import concurrent.futures
import ssl
import pandas as pd
import requests
from datetime import datetime

st.set_page_config(page_title="Domain Reputation & Health Checker", layout="wide")

# --- Configuration & Core Functions ---

def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert["notAfter"]
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.now()).days
                return f"{days_left}d", days_left > 7
    except Exception:
        return "NoSSL/Error", False

def check_dnsbl(domain, zone, friendly_name):
    try:
        query = f"{domain}.{zone}"
        dns.resolver.resolve(query, "A")
        return friendly_name
    except Exception:
        return None

def check_google_safe_browsing(domain, api_key):
    if not api_key:
        return "Missing API Key"
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "domain-checker", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": f"http://{domain}"}, {"url": f"https://{domain}"}]
        }
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200 and response.json():
            return "FLAGGED"
        return "CLEAN"
    except Exception:
        return "API ERROR"

def check_virustotal(domain, api_key):
    if not api_key:
        return "Missing API Key"
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            phishing = stats.get("phishing", 0)
            if malicious > 0 or phishing > 0:
                return f"FLAGGED ({malicious + phishing} engines)"
        return "CLEAN"
    except Exception:
        return "API ERROR"

def check_urlhaus(domain):
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    try:
        response = requests.post(url, data={"host": domain}, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok" and data.get("blacklisted") == "yes":
                return "FLAGGED"
        return "CLEAN"
    except Exception:
        return "API ERROR"

def analyze_domain(domain, google_key, vt_key, spamhaus_key):
    domain = domain.strip().lower()
    if not domain:
        return None
    
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {
            "Domain": domain, "SSL": "-", "DNS Status": "DOWN",
            "Google Safe Browsing": "-", "VirusTotal": "-", "URLHaus": "-",
            "DNS Blocklists": "UNRESOLVABLE", "Status": "BAD"
        }

    ssl_val, ssl_ok = check_ssl_expiry(domain)
    
    # DNS-based checks
    detected_bls = []
    surbl = check_dnsbl(domain, "multi.surbl.org", "SURBL")
    sorbs = check_dnsbl(domain, "uribl.rhsbl.sorbs.net", "SORBS")
    
    if surbl: detected_bls.append(surbl)
    if sorbs: detected_bls.append(sorbs)
    
    # Custom Spamhaus DQS check if key exists
    if spamhaus_key:
        spamhaus = check_dnsbl(f"{domain}.{spamhaus_key}", "dbl.spamhaus.org", "Spamhaus DBL")
        if spamhaus: detected_bls.append(spamhaus)
    else:
        # Check standard if no key, but remember it acts false-clean in cloud environments
        spamhaus = check_dnsbl(domain, "dbl.spamhaus.org", "Spamhaus DBL")
        if spamhaus: detected_bls.append(spamhaus)

    gsb = check_google_safe_browsing(domain, google_key)
    vt = check_virustotal(domain, vt_key)
    urlhaus = check_urlhaus(domain)
    
    bl_summary = ", ".join(detected_bls) if detected_bls else "CLEAN"
    
    is_clean = (
        ssl_ok and 
        not detected_bls and 
        gsb == "CLEAN" and 
        vt == "CLEAN" and 
        urlhaus == "CLEAN"
    )

    return {
        "Domain": domain,
        "SSL": ssl_val,
        "DNS Blocklists": bl_summary,
        "Google Safe Browsing": gsb,
        "VirusTotal": vt,
        "URLHaus": urlhaus,
        "Status": "GOOD" if is_clean else "BAD"
    }

def style_row(row):
    if row["Status"] == "GOOD":
        style = "background-color: #d4f4dd; color: #0b3d1f; font-weight: 600;"
    else:
        style = "background-color: #fbdcdc; color: #5c0d0d; font-weight: 600;"
    return [style] * len(row)

# --- UI Layout ---

hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.title("🔗 Expanded Redirect Domain Checker")
st.caption("Checks SSL expiration and maps domains against multi-source threat intelligence platforms.")

GOOGLE_API_KEY = st.secrets.get("GOOGLE_SAFE_BROWSING_KEY", "")
VIRUSTOTAL_API_KEY = st.secrets.get("VIRUSTOTAL_KEY", "")
SPAMHAUS_DQS_KEY = st.secrets.get("SPAMHAUS_DQS_KEY", "")

domains_input = st.text_area(
    "Paste domains (one per line)",
    height=150,
    placeholder="example.com",
)

if st.button("Run Comprehensive Check", type="primary"):
    domains = [d.strip() for d in domains_input.splitlines() if d.strip()]
    if not domains:
        st.warning("Add at least one domain first.")
    else:
        progress = st.progress(0, text="Initializing scanning...")
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(analyze_domain, d, GOOGLE_API_KEY, VIRUSTOTAL_API_KEY, SPAMHAUS_DQS_KEY): d for d in domains}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
                done += 1
                progress.progress(done / len(domains), text=f"Checked {done}/{len(domains)}")
        progress.empty()

        df = pd.DataFrame(results)
        st.subheader("Analysis Results")
        st.dataframe(df.style.apply(style_row, axis=1), use_container_width=True)

        ready = df[df["Status"] == "GOOD"]["Domain"].tolist()
        st.subheader("✅ Clean / Verified Domains")
        if ready:
            st.code("\n".join(ready))
        else:
            st.info("No completely clean domains identified in this batch.")

        # --- Your Custom Warning Message Box ---
        st.markdown(
            """
            <div style="background-color:#2b1414; border-left: 4px solid #ff4d4d;
                        border-radius: 8px; padding: 16px 20px; margin-top: 24px;">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                    <span style="font-size:20px;">⚠️</span>
                    <span style="color:#ff6b6b; font-weight:700; font-size:16px;">
                        Before you launch any drops
                    </span>
                </div>
               <p style="color:#e6e6e6; font-size:14px; line-height:1.6; margin:0 0 14px 0;">
    Every selected domain must be manually double-checked before use.
    Confirm that it is not listed on Spamhaus or any other blacklist.
    Prefer to use domains that come back clean.
    Do not launch on a domain that is flagged.
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

st.markdown(
    """
    <div style="text-align: center; margin-top: 60px; padding: 16px 0;
                color: #6b7280; font-size: 14px; letter-spacing: 0.3px;">
        ⚡ No plan, just flow — <span style="color:#a78bfa; font-weight:600;">vibe coded</span>
        by <span style="color:#34d399; font-weight:600;">Ascended696</span>
    </div>
    """,
    unsafe_allow_html=True,
)
