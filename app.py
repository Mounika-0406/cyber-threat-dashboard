import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="Cyber Threat Dashboard", layout="wide", page_icon="🛡️")

# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    }
    .login-card {
        background-color: #ffffff;
        padding: 50px 40px;
        border-radius: 20px;
        max-width: 420px;
        margin: 60px auto 0 auto;
        box-shadow: 0 12px 40px rgba(0,0,0,0.4);
        text-align: center;
    }
    .login-icon { font-size: 50px; margin-bottom: 10px; }
    .login-title { font-size: 26px; font-weight: 700; color: #1a1a2e; margin-bottom: 5px; }
    .login-subtitle { font-size: 14px; color: #666; margin-bottom: 30px; }
    div.stButton > button {
        background-color: #2c5364;
        color: white;
        border-radius: 8px;
        padding: 10px 0;
        font-weight: 600;
        border: none;
        width: 100%;
    }
    div.stButton > button:hover { background-color: #1a3a47; color: white; }
    .login-footer { font-size: 12px; color: #999; margin-top: 20px; }
    h1, h2, h3 { color: white !important; }
    .severity-high { color: #ff4b4b; font-weight: bold; }
    .severity-medium { color: #ffa500; font-weight: bold; }
    .severity-low { color: #2ecc71; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# ---------------- LOGIN PAGE ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

CORRECT_PASSWORD = "threat2026"   # <-- change this to any password you want

if not st.session_state.logged_in:
    _, mid, _ = st.columns([1, 1.2, 1])
    with mid:
        st.markdown("""
        <div class="login-card">
            <div class="login-icon">🛡️</div>
            <div class="login-title">Threat Intelligence Portal</div>
            <div class="login-subtitle">Cybercrime Log Analysis & Threat Distribution System</div>
        </div>
        """, unsafe_allow_html=True)

        name = st.text_input("Analyst Name", placeholder="e.g. Mounika")
        role = st.selectbox("Role", ["Security Analyst", "SOC Manager", "Administrator"])
        password = st.text_input("Password", type="password", placeholder="Enter access code")

        if st.button("Sign In"):
            if name.strip() == "":
                st.warning("Please enter your name")
            elif password != CORRECT_PASSWORD:
                st.error("Incorrect password. Access denied.")
            else:
                st.session_state.logged_in = True
                st.session_state.user_name = name
                st.session_state.user_role = role
                st.rerun()

        st.markdown('<div class="login-footer">Authorized personnel only</div>', unsafe_allow_html=True)

# ---------------- DASHBOARD (after login) ----------------
else:
    st.title(f"🛡️ Welcome, {st.session_state.user_name}")
    st.caption(f"Logged in as: {st.session_state.user_role}")

    df = pd.read_csv("cyber_logs.csv", parse_dates=["timestamp"])
    attacks = df[df["label"] != "Normal"]

    st.markdown(f"""
    <div style="background-color:#ff4b4b;color:white;padding:12px 20px;border-radius:8px;font-weight:bold;margin-bottom:20px;">
        ⚠️ {len(attacks)} attack events detected out of {len(df)} total logged events
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Events", len(df))
    col2.metric("Threat Types", df["label"].nunique())
    col3.metric("Attack Events", len(attacks))

    label_counts = df["label"].value_counts()

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Threat Distribution")
        fig, ax = plt.subplots()
        ax.pie(label_counts, labels=label_counts.index, autopct="%1.1f%%")
        st.pyplot(fig)

    with c2:
        st.subheader("Event Count per Threat Type")
        st.bar_chart(label_counts)

    df["date"] = df["timestamp"].dt.date
    st.subheader("Events Over Time by Threat Type")
    time_series = df.groupby(["date", "label"]).size().unstack(fill_value=0)
    st.line_chart(time_series)

    st.subheader("Top Source IPs by Attack Volume")
    top_ips = attacks["source_ip"].value_counts().head(10)
    st.bar_chart(top_ips)

    st.subheader("Threat Severity Levels")
    severity_map = {
        "DDoS": "High", "Malware C2": "High", "Brute Force": "Medium",
        "Unauthorized Access": "High", "Phishing/Web Attack": "Medium",
        "Port Scan": "Low", "Normal": "Low"
    }
    for threat, sev in severity_map.items():
        css_class = f"severity-{sev.lower()}"
        st.markdown(f"**{threat}**: <span class='{css_class}'>{sev}</span>", unsafe_allow_html=True)

    st.subheader("Explore Raw Logs")
    threat_filter = st.multiselect("Filter by threat type", options=df["label"].unique(), default=list(df["label"].unique()))
    st.dataframe(df[df["label"].isin(threat_filter)].head(200))

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()
