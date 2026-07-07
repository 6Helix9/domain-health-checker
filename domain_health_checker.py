import streamlit as st
import dns.resolver
import socket
import concurrent.futures
import ssl
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="Domain Health Checker", layout="wide")

YAHOO_RBLS = {
    "zen.spamhaus.org": "Spamhaus",
    "bl.spamcop.net": "Spamcop",
    "b.barracudacentral.org": "Barracuda",
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


def check_dns(domain):
    def check_rec(q, t, pattern):
        try:
            res = dns.resolver.resolve(q, t)
            for r in res:
                if pattern in r.to_text():
                    return "OK", True
            return ("OK", True) if pattern == "" else ("OFF", False)
        except Exception:
            return "OFF", False

    mx = check_rec(domain, "MX", "")
    spf = check_rec(domain, "TXT", "v=spf1")
    dmarc = check_rec(f"_dmarc.{domain}", "TXT", "v=DMARC1")
    return mx, spf, dmarc


def check_blacklist(ip):
    if not ip:
        return "N/A", []
    rev = ".".join(reversed(ip.split(".")))
    listed = []
    for url, name in YAHOO_RBLS.items():
        try:
            dns.resolver.resolve(f"{rev}.{url}", "A")
            listed.append(name)
        except Exception:
            continue
    if "Spamhaus" in listed:
        return "BLACKHOLE", listed
    if listed:
        return "LISTED", listed
    return "CLEAN", []


def analyze_domain(domain):
    domain = domain.strip()
    if not domain:
        return None
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {
            "Domain": domain, "MX": "-", "SPF": "-", "DMARC": "-",
            "SSL": "-", "Reputation": "DNS DOWN / NO IP", "Sources": "",
            "Status": "BAD",
        }

    mx, spf, dmarc = check_dns(domain)
    rep_status, rbl_list = check_blacklist(ip)
    ssl_val, ssl_ok = check_ssl_expiry(domain)

    is_good = (rep_status == "CLEAN" and mx[1] and ssl_val != "NoSSL")

    return {
        "Domain": domain,
        "MX": "OK" if mx[1] else "OFF",
        "SPF": "OK" if spf[1] else "OFF",
        "DMARC": "OK" if dmarc[1] else "OFF",
        "SSL": ssl_val,
        "Reputation": rep_status,
        "Sources": ", ".join(rbl_list),
        "Status": "GOOD" if is_good else "BAD",
    }


def style_row(row):
    color = "background-color: #d4f4dd" if row["Status"] == "GOOD" else "background-color: #fbdcdc"
    return [color] * len(row)


st.title("🌐 Domain Health Checker")
st.caption("Checks MX, SPF, DMARC, SSL expiry, and blacklist status for a list of domains.")

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
        st.subheader("✅ Ready / Clean Domains")
        if ready:
            st.code("\n".join(ready))
        else:
            st.info("No clean domains found.")

        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download results as CSV", csv, "domain_health_results.csv", "text/csv")
