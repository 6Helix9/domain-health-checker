import streamlit as st
import dns.resolver
import socket
import concurrent.futures
import ssl
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="Redirect Domain Checker", layout="wide")

# --- Domain/URI blocklists (these check the DOMAIN itself, not a sending IP) ---
URI_BLOCKLISTS = {
    "dbl.spamhaus.org": "Spamhaus DBL",
    "multi.surbl.org": "SURBL",
    "uribl.rhsbl.sorbs.net": "SORBS RHSBL",
}


def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert["notAfter"]
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.now()).days
                return f"{days_left}d", days_left > 7
    except Exception:
        return "NoSSL", False


def check_domain_blocklists(domain):
    listed = []
    for zone, name in URI_BLOCKLISTS.items():
        try:
            query = f"{domain}.{zone}"
            dns.resolver.resolve(query, "A")
            listed.append(name)
        except Exception:
            continue
    if listed:
        return "LISTED", listed
    return "CLEAN", []


def check_ip_blacklist(ip):
    if not ip:
        return "N/A", []
    rev = ".".join(reversed(ip.split(".")))
    listed = []
    for url, name in {"zen.spamhaus.org": "Spamhaus IP"}.items():
        try:
            dns.resolver.resolve(f"{rev}.{url}", "A")
            listed.append(name)
        except Exception:
            continue
    return ("LISTED", listed) if listed else ("CLEAN", [])


def analyze_domain(domain):
    domain = domain.strip()
    if not domain:
        return None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {
            "Domain": domain, "SSL": "-", "Domain Blocklist": "DNS DOWN",
            "Blocklist Sources": "", "IP Blacklist": "-", "Status": "BAD",
        }

    ssl_val, ssl_ok = check_ssl_expiry(domain)
    domain_bl_status, domain_bl_sources = check_domain_blocklists(domain)
    ip_bl_status, ip_bl_sources = check_ip_blacklist(ip)

    is_good = (domain_bl_status == "CLEAN" and ssl_val != "NoSSL" and ip_bl_status == "CLEAN")

    return {
        "Domain": domain,
        "SSL": ssl_val,
        "Domain Blocklist": domain_bl_status,
        "Blocklist Sources": ", ".join(domain_bl_sources),
        "IP Blacklist": ip_bl_status,
        "Status": "GOOD" if is_good else "BAD",
    }


def style_row(row):
    if row["Status"] == "GOOD":
        style = "background-color: #d4f4dd; color: #0b3d1f; font-weight: 600;"
    else:
        style = "background-color: #fbdcdc; color: #5c0d0d; font-weight: 600;"
    return [style] * len(row)


hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.title("🔗 Redirect Domain Checker")
st.caption(
    "Checks whether domains are safe to use as REDIRECT/LINK domains in email bodies: "
    "SSL validity, and domain/URI blocklist status (Spamhaus DBL, SURBL, SORBS)."
)

domains_input = st.text_area(
    "Paste domains (one per line)",
    height=200,
    placeholder="example.com\nanotherdomain.com",
)

max_workers = st.slider("Parallel checks", min_value=1, max_value=20, value=10)

if st.button("Run Health Check", type="primary"):
    domains = [d.strip() for d in domains_input.splitlines() if d.strip()]
    if not domains:
        st.warning("Add at least one domain first.")
    else:
        progress = st.progress(0, text="Starting...")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(analyze_domain, d): d for d in domains}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
                done += 1
                progress.progress(done / len(domains), text=f"Checked {done}/{len(domains)}")
        progress.empty()

        df = pd.DataFrame(results)
        st.subheader("Results")
        st.dataframe(df.style.apply(style_row, axis=1), use_container_width=True)

        ready = df[df["Status"] == "GOOD"]["Domain"].tolist()
        st.subheader("✅ Ready / Clean Redirect Domains")
        if ready:
            st.code("\n".join(ready))
        else:
            st.info("No clean domains found.")

        st.markdown(
            """
            <p style="color:red; font-weight:bold;">
            ⚠️ Important: Before launching any drops, every selected domain must also be checked at
            <a href="https://multirbl.valli.org/lookup" style="color:red;">multirbl.valli.org/lookup</a>
            to confirm it isn't listed on Spamhaus or any other blacklist. Don't launch on a domain that comes back flagged.
            </p>
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
