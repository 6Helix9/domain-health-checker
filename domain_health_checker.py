import streamlit as st
import dns.resolver
import concurrent.futures
import pandas as pd

# --- Page Configuration ---
st.set_page_config(
    page_title="Blacklist Monitoring",
    page_icon="🛡️",
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
    .kpi-card.blue { border-left: 4px solid #3b82f6; }
    .kpi-card.green { border-left: 4px solid #10b981; }
    .kpi-card.red { border-left: 4px solid #ef4444; }
    
    .kpi-label {
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 1.5px;
        color: #9ca3af;
        margin-bottom: 6px;
        font-weight: 700;
    }
    .kpi-value {
        font-size: 24px;
        font-weight: 700;
        color: #ffffff;
    }

    /* Info Alert Card */
    .info-card {
        background: rgba(59, 130, 246, 0.05);
        border: 1px solid rgba(59, 130, 246, 0.2);
        border-radius: 12px;
        padding: 16px 20px;
        display: flex;
        align-items: center;
        gap: 12px;
        margin-top: 24px;
    }
    .info-text {
        font-size: 11px;
        line-height: 1.6;
        color: #9ca3af;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# --- Configuration & Core Functions ---

DNSBL_SOURCES = {
    'Spamhaus': 'zen.spamhaus.org',
    'SpamCop': 'bl.spamcop.net',
    'Barracuda': 'b.barracudacentral.org',
    'SORBS': 'dnsbl.sorbs.net',
    'SpamRats': 'all.spamrats.com',
    'UCEPROTECT': 'dnsbl-1.uceprotect.net',
    'PSBL': 'psbl.surriel.com'
}

def reverse_ip(ip):
    """Reverses IP for DNSBL querying (e.g., 1.2.3.4 -> 4.3.2.1)"""
    return ".".join(reversed(ip.split(".")))

def check_single_dnsbl(ip, zone):
    try:
        query = f"{reverse_ip(ip)}.{zone}"
        dns.resolver.resolve(query, "A")
        return "Listed"
    except dns.resolver.NXDOMAIN:
        return "Clean"
    except Exception:
        return "Unknown"

def analyze_ip_reputation(ip, domain):
    ip = ip.strip()
    result_row = {"Node / IP": ip, "PTR / Domain": domain}
    is_listed = False
    
    # Process all lists for this specific IP
    for source_name, zone in DNSBL_SOURCES.items():
        status = check_single_dnsbl(ip, zone)
        result_row[source_name] = status
        if status == "Listed":
            is_listed = True
            
    return result_row, is_listed

def style_df_rows(row):
    """Styles the dataframe dynamically based on status matching the React UI"""
    styles = []
    for col in row.index:
        if col in ["Node / IP", "PTR / Domain"]:
            styles.append("background-color: #161a1f; color: #f3f4f6; border-bottom: 1px solid #1f2937;")
        else:
            val = row[col]
            if val == "Clean":
                styles.append("background-color: rgba(16, 185, 129, 0.08); color: #34d399; font-weight: 700; text-align: center; border-bottom: 1px solid #1f2937;")
            elif val == "Listed":
                styles.append("background-color: rgba(239, 68, 68, 0.08); color: #f87171; font-weight: 700; text-align: center; text-shadow: 0 0 8px #f87171; border-bottom: 1px solid #1f2937;")
            else:
                styles.append("background-color: rgba(156, 163, 175, 0.05); color: #9ca3af; text-align: center; border-bottom: 1px solid #1f2937;")
    return styles

# --- Master Layout Assembly ---

st.markdown("<h2 style='margin-bottom:0px; font-weight:700;'>🛡️ Blacklist Monitoring</h2>", unsafe_allow_html=True)
st.markdown("<p style='color:#9ca3af; font-size:14px; margin-bottom:32px;'>Track IP and Domain reputation across 7 major providers.</p>", unsafe_allow_html=True)

infrastructure_input = st.text_area(
    "Infrastructure Targets",
    height=140,
    placeholder="Format: IP, Domain (e.g., 192.168.1.1, example.com)\nEnter one per line.",
    label_visibility="collapsed"
)

if st.button("Check All Repository", type="primary"):
    lines = [line.strip() for line in infrastructure_input.splitlines() if line.strip()]
    
    if not lines:
        st.error("No infrastructure found to monitor. Please add IPs first.")
    else:
        # Parse inputs
        target_list = []
        for line in lines:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                target_list.append((parts[0], parts[1]))
            else:
                target_list.append((parts[0], "Unknown Domain"))
                
        scan_progress = st.progress(0, text="Starting bulk DNSBL reputation check...")
        
        dataset = []
        total_count = len(target_list)
        listed_count = 0
        
        # Concurrent execution 
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as worker_pool:
            future_to_ip = {
                worker_pool.submit(analyze_ip_reputation, ip, dom): ip 
                for ip, dom in target_list
            }
            completed = 0
            for future in concurrent.futures.as_completed(future_to_ip):
                row_data, is_listed = future.result()
                dataset.append(row_data)
                if is_listed:
                    listed_count += 1
                    
                completed += 1
                scan_progress.progress(completed / total_count, text=f"Checked {completed}/{total_count}")
        
        scan_progress.empty()
        
        # Render KPIs
        clean_count = total_count - listed_count
        
        st.markdown(f"""
        <div class="kpi-container">
            <div class="kpi-card blue">
                <div class="kpi-label">Total Monitored</div>
                <div class="kpi-value">{total_count}</div>
            </div>
            <div class="kpi-card green">
                <div class="kpi-label">Clean IPs</div>
                <div class="kpi-value" style="color: #34d399;">{clean_count}</div>
            </div>
            <div class="kpi-card red">
                <div class="kpi-label">Listed / Blacklisted</div>
                <div class="kpi-value" style="color: #f87171;">{listed_count}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Render Table
        df = pd.DataFrame(dataset)
        
        # Ensure column order matches the React app
        cols = ["Node / IP", "PTR / Domain"] + list(DNSBL_SOURCES.keys())
        df = df[cols]

        st.dataframe(
            df.style.apply(style_df_rows, axis=1), 
            use_container_width=True,
            hide_index=True
        )

        # Network Exhaustion Warning[cite: 1]
        st.markdown("""
        <div class="info-card">
            <div style="color: #3b82f6; font-size: 20px;">⚠️</div>
            <div class="info-text">
                System queries direct DNSBL nodes automatically. If querying a large global fleet, use a dedicated DNS resolver to minimize latency and prevent network UDP exhaustion.
            </div>
        </div>
        """, unsafe_allow_html=True)

st.markdown(
    """
    <div style="text-align: center; margin-top: 40px; padding: 24px 0; border-top: 1px solid #1f2937;
                color: #4b5563; font-size: 13px; letter-spacing: 0.5px;">
        ⚡ No plan, just flow — <span style="color:#a78bfa; font-weight:600;">vibe coded</span>
        by <span style="color:#3b82f6; font-weight:600;">Ascended696</span>
    </div>
    """,
    unsafe_allow_html=True,
)
