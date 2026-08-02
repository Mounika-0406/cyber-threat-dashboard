import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="Cyber Threat Dashboard", layout="wide")
st.title("🛡️ Cybercrime Log Analysis & Threat Distribution")

df = pd.read_csv("cyber_logs.csv", parse_dates=["timestamp"])

col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(df))
col2.metric("Threat Types", df["label"].nunique())
col3.metric("Attack Events", int((df["label"] != "Normal").sum()))

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
attacks = df[df["label"] != "Normal"]
top_ips = attacks["source_ip"].value_counts().head(10)
st.bar_chart(top_ips)

st.subheader("Explore Raw Logs")
threat_filter = st.multiselect("Filter by threat type", options=df["label"].unique(), default=list(df["label"].unique()))
st.dataframe(df[df["label"].isin(threat_filter)].head(200))
