import streamlit as st
import dns.resolver
import socket
import concurrent.futures
import ssl
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="Redirect Domain Checker", layout="wide")

# Spamhaus's official "query blocked" return codes. These do NOT mean
# "not listed" — they mean Spamhaus refused to answer at all (usually
# because the query came from a cloud/datacenter IP without proper
# reverse DNS, which is exactly what Streamlit Cloud is). Any tool that
# treats these as "clean" produces dangerous false negatives.
SPAMHAUS_BLOCKED_CODES = {"127.255.255.254", "127.255.255.255"}

# Secondary domain/URI blocklists (best-effort — not officially rate-limit
# tagged like Spamhaus, so treated as supporting signals only)
SECONDARY_URI_BLOCKLISTS = {
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


def check_spamhaus_dbl(domain, dqs_key=None):
    """Check Spamhaus DBL — the most important domain blocklist.
    Uses the paid-free DQS key if provided (reliable, no blocking).
    Falls back to the public mirror otherwise, but explicitly detects
    Spamhaus's "query blocked" codes instead of silently reporting clean."""
    if dqs_key:
        query = f"{domain}.{dqs_key.strip()}.dbl.dq.spamhaus.net"
    else:
        query = f"{domain}.dbl.spamhaus.org"

    try:
        answers = dns.resolver.resolve(query, "A")
        ips = [r.to_text() for r in answers]
        if any(ip in SPAMHAUS_BLOCKED_CODES for ip in ips):
            return "BLOCKED/UNKNOWN"
        return "LISTED"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Genuinely not listed IF we have a DQS key (reliable).
        # Without a key, this could ALSO mean a silent public-mirror block —
        # Spamhaus's own docs confirm blocked public queries often return
        # NXDOMAIN instead of an error code, so we flag this honestly.
        return "CLEAN" if dqs_key else "CLEAN (unverified - no DQS key)"
    except Exception:
        return "CHECK FAILED"


def check_secondary_blocklists(domain):
    listed = []
    for zone, name in SECONDARY_URI_BLOCKLISTS.items():
        try:
            dns.resolver.resolve(f"{domain}.{zone}", "A")
            listed.append(name)
        except Exception:
            continue
    return listed


def check_ip_blacklist(ip, dqs_key=None):
    if not ip:
        return "N/A"
    rev = ".".join(reversed(ip.split(".")))
    query = f"{rev}.{dqs_key.strip()}.zen.dq.spamhaus.net" if dqs_key else f"{rev}.zen.spamhaus.org"
    try:
        answers = dns.resolver.resolve(query, "A")
        ips = [r.to_text() for r in answers]
        if any(i in SPAMHAUS_BLOCKED_CODES for i in ips):
            return "BLOCKED/UNKNOWN"
        return "LISTED"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "CLEAN" if dqs_key else "CLEAN (unverified - no DQS key)"
    except Exception:
        return "CHECK FAILED"


def analyze_domain(domain, dqs_key=None):
    domain = domain.strip()
    if not domain:
        return None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {
            "Domain": domain, "SSL": "-", "Spamhaus DBL": "DNS DOWN",
            "Other Blocklists": "", "IP Blacklist": "-", "Status": "BAD",
        }

    ssl_val, ssl_ok = check_ssl_expiry(domain)
    dbl_status = check_spamhaus_dbl(domain, dqs_key)
    secondary_hits = check_secondary_blocklists(domain)
    ip_bl_status = check_ip_blacklist(ip, dqs_key)

    is_bad = (
        dbl_status.startswith("LISTED")
        or dbl_status == "BLOCKED/UNKNOWN"
        or ssl_val == "NoSSL"
        or bool(secondary_hits)
        or ip_bl_status.startswith("LISTED")
        or ip_bl_status == "BLOCKED/UNKNOWN"
    )

    return {
        "Domain": domain,
        "SSL": ssl_val,
        "Spamhaus DBL": dbl_status,
        "Other Blocklists": ", ".join(secondary_hits) if secondary_hits else "CLEAN",
        "IP Blacklist": ip_bl_status,
        "Status": "BAD" if is_bad else "GOOD",
    }


def style_row(row):
    if row["Status"] == "GOOD":
        style = "background-color: #d4f4dd; color: #0b3d1f; font-weight: 600;"
    elif "UNKNOWN" in str(row.get("Spamhaus DBL", "")) or "unverified" in str(row.get("Spamhaus DBL", "")):
        style = "background-color: #fff3cd; color: #664d03; font-weight: 600;"
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
    "SSL validity and domain blocklist status (Spamhaus DBL, SURBL, SORBS)."
)

with st.expander("⚠️ Read this: about Spamhaus accuracy"):
    st.markdown(
        "Spamhaus blocks free public DNS queries coming from cloud/datacenter IPs "
        "(like this app's hosting) and returns responses that look like **\"not "
        "listed\"** even when a domain IS actually listed. Without a Spamhaus **DQS "
        "key** (free, from spamhaus.com), results are labeled *unverified*. "
        "[Get a free DQS key here](https://www.spamhaus.com/data-access/free-data-query-service/) "
        "for fully reliable results."
    )

dqs_key = st.text_input(
    "Spamhaus DQS key (optional, but recommended for accurate results)",
    value="bd3jsvcgugoqmqe2b5ehvgjdaa",
    type="password",
    placeholder="26-character key from your Spamhaus account",
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
            futures = {executor.submit(analyze_domain, d, dqs_key): d for d in domains}
            done = 0
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results.append(res)
                done += 1
                progress.progress(done / len(domains), text=f"Checked {done}/{len(domains)}")
        progress.empty()

        if not dqs_key:
            st.warning(
                "No Spamhaus DQS key entered — 'CLEAN' results are unverified and "
                "may miss real listings. Add a free key above for reliable results."
            )

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
