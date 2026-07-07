import streamlit as st
import dns.resolver
import socket
import concurrent.futures
import ssl
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="Redirect Domain Checker", layout="wide")

# --- Domain/URI blocklists (these check the DOMAIN itself, not a sending IP) ---
# These are the lists email filters actually consult when scanning links
# INSIDE an email body — exactly what matters for a redirect domain.
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
    """Check if the DOMAIN ITSELF is listed on URI/domain blocklists.
    This is what matters for redirect/link domains, since filters resolve
    the domain inside every link in the email body against these lists."""
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
    """Secondary check: is the IP the redirect domain resolves to blacklisted?
    Less critical than the domain-level check above, but a domain hosted on
    a known-bad IP is still worth flagging."""
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

    # For a REDIRECT domain: what matters is it resolves, has valid SSL
    # (so the link doesn't throw a security warning), and isn't on a
    # domain/URI blocklist. Sending-domain checks (MX/SPF/DKIM/DMARC) don't
    # apply here since this domain never sends mail.
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

        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download results as CSV", csv, "domain_health_results.csv", "text/csv")

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
