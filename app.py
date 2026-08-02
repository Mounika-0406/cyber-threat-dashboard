import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="Cyber Threat Dashboard", layout="wide", page_icon="🛡️")

# ---------------- CUSTOM CSS (this replaces a separate .css file) ----------------
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    }
    .login-box {
        background-color: white;
        padding: 40px;
        border-radius: 15px;
        max-width: 420px;
        margin: 80px auto;
        box-shadow: 0 8px 30px rgba(0,0,0,0.3);
    }
    .metric-card {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 10px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .alert-banner {
        background-color: #ff4b4b;
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        font-weight: bold;
        margin-bottom: 20px;
    }
    h1, h2, h3 { color: white !important; }
    .severity-high { color: #ff4b4b; font-weight: bold; }
    .severity-medium { color: #ffa500; font-weight: bold; }
    .severity-low { color: #2ecc71; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# ---------------- LOGIN PAGE ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.markdown('<div class="login-box">', unsafe_allow_html=True)
    st.markdown("### 🔐 Security Dashboard Login")
    name = st.text_input("Analyst Name")
    role = st.selectbox("Role", ["Security Analyst", "SOC Manager", "Administrator"])
    if st.button("Login", use_container_width=True):
        if name.strip() != "":
            st.session_state.logged_in = True
            st.session_state.user_name = name
            st.session_state.user_role = role
            st.rerun()
        else:
            st.warning("Please enter your name")
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- DASHBOARD (after login) ----------------
else:
    st.title(f"🛡️ Welcome, {st.session_state.user_name}")
    st.caption(f"Logged in as: {st.session_state.user_role}")

    df = pd.read_csv("cyber_logs.csv", parse_dates=["timestamp"])
    attacks = df[df["label"] != "Normal"]

    # Alert banner
    st.markdown(f"""
    <div class="alert-banner">
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

    # Severity mapping
    st.subheader("Threat Severity Levels")
    severity_map = {
        "DDoS": "High", "Malware C2": "High", "Brute Force": "Medium",
        "Unauthorized Access": "High", "Phishing/Web Attack": "Medium",
        "Port Scan": "Low", "Normal": "Low"
    }
    sev_df = pd.DataFrame(list(severity_map.items()), columns=["Threat Type", "Severity"])
    for _, row in sev_df.iterrows():
        css_class = f"severity-{row['Severity'].lower()}"
        st.markdown(f"**{row['Threat Type']}**: <span class='{css_class}'>{row['Severity']}</span>", unsafe_allow_html=True)

    st.subheader("Explore Raw Logs")
    threat_filter = st.multiselect("Filter by threat type", options=df["label"].unique(), default=list(df["label"].unique()))
    st.dataframe(df[df["label"].isin(threat_filter)].head(200))

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()
