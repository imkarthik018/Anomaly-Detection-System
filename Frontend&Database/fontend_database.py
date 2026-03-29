# Deprecated: use the Flask app in ../WebFrontend/app.py instead of Streamlit.
import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv

    load_dotenv(_ROOT / ".env")
except ImportError:
    pass

import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import tempfile
import altair as alt
from sqlalchemy import create_engine
from datetime import datetime

# -----------------------
# CONFIG - Email Settings (use Gmail App Password, not your normal password)
# -----------------------
EMAIL_ADDRESS = (os.environ.get("EMAIL_ADDRESS") or "xxxxxxxxxx@gmail.com").strip()
EMAIL_PASSWORD = (os.environ.get("EMAIL_PASSWORD") or "xxxxxxxxxxxxxxxx").replace(" ", "").strip()
TO_EMAIL = (os.environ.get("TO_EMAIL") or "vjkarthiabi@gmail.com").strip()

# -----------------------
# CONFIG - Database (default: SQLite file in project root; set DATABASE_URL for PostgreSQL)
# -----------------------
_DEFAULT_SQLITE = f"sqlite:///{(_ROOT / 'login_anomalies.db').resolve().as_posix()}"
DATABASE_URL = os.environ.get("DATABASE_URL", _DEFAULT_SQLITE)

# -----------------------
# Streamlit Page Config
# -----------------------
st.set_page_config(page_title="Anomaly Detection", layout="wide")

st.markdown("""
<style>
    .main {
        background-color: #f7f9fc;
    }
    .title {
        text-align: center;
        color: #2c3e50;
        font-size: 40px !important;
        font-weight: bold;
    }
    table {
        border-radius: 10px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("<h1 class='title'>Anomaly Detection</h1>", unsafe_allow_html=True)

# -----------------------
# File Upload
# -----------------------
uploaded_file = st.file_uploader("📂 Upload your CSV file", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # Filter only login events
    df = df[df["activity_type"].str.lower() == "login"].reset_index(drop=True)

    if df.empty:
        st.error("No login records found in the uploaded file.")
        st.stop()

    # Encode categorical features
    encoder_loc = LabelEncoder()
    encoder_ip = LabelEncoder()

    if "location" in df.columns:
        df["location_encoded"] = encoder_loc.fit_transform(df["location"])
    else:
        st.error("❌ Missing required column: 'location'")
        st.stop()

    if "ip_address" in df.columns:  # using ip_address instead of source_ip
        df["ip_encoded"] = encoder_ip.fit_transform(df["ip_address"])
    else:
        st.error("❌ Missing required column: 'ip_address'")
        st.stop()

    # -----------------------
    # Train Isolation Forest
    # -----------------------
    X = df[["location_encoded", "ip_encoded"]]
    model = IsolationForest(contamination=0.01, random_state=42)

    # Fit & predict
    df["anomaly_flag"] = pd.Series(model.fit_predict(X)).map({1: 0, -1: 1})
    df["anomaly_score"] = model.decision_function(X)

    anomalies = df[df["anomaly_flag"] == 1]

    # -----------------------
    # KPIs
    # -----------------------
    col1, col2 = st.columns(2)
    col1.metric("Total Logins", len(df))
    col2.metric("Detected Anomalies", len(anomalies))

    # -----------------------
    # Highlight anomalies
    # -----------------------
    def highlight_anomalies(row):
        color = 'background-color: #ffcccc' if row['anomaly_flag'] == 1 else ''
        return [color] * len(row)

    st.subheader("📊 Detection Results")
    st.dataframe(df.style.apply(highlight_anomalies, axis=1), use_container_width=True)

    # -----------------------
    # Chart for anomalies over time
    # -----------------------
    if "timestamp" in df.columns:
        try:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            chart = alt.Chart(anomalies).mark_bar(color="red").encode(
                x='timestamp:T',
                y='count()',
                tooltip=['timestamp:T', 'count()']
            ).properties(title='Anomalies Over Time')
            st.altair_chart(chart, use_container_width=True)
        except Exception as e:
            st.warning(f"Chart could not be generated: {e}")

    # -----------------------
    # Save anomalies to PostgreSQL & Send Email
    # -----------------------
    if not anomalies.empty:
        try:
            # Add insertion timestamp
            anomalies["insertion_time"] = datetime.utcnow()

            # Save to PostgreSQL
            engine = create_engine(DATABASE_URL)
            anomalies.to_sql("login_anomalies", engine, if_exists="append", index=False)
            st.success("📦 Anomaly data successfully saved to cloud database.")
        except Exception as e:
            st.error(f"❌ Failed to save to database: {e}")

        try:
            # Create HTML table for email
            html_table = anomalies.to_html(index=False)

            # Save anomalies to temp CSV
            with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
                anomalies.to_csv(tmp.name, index=False)
                csv_path = tmp.name

            # Email setup
            msg = MIMEMultipart()
            msg['From'] = EMAIL_ADDRESS
            msg['To'] = TO_EMAIL
            msg['Subject'] = "🚨 Login Anomaly Alert"

            body = f"""
            <h2>Login Anomaly Alert</h2>
            <p>Detected {len(anomalies)} unusual login attempts.</p>
            {html_table}
            """
            msg.attach(MIMEText(body, 'html'))

            # Attach CSV
            with open(csv_path, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename=anomalies.csv")
                msg.attach(part)

            # Send email
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)  # App Password: spaces removed above
            server.send_message(msg)
            server.quit()

            st.success(f"✅ Email sent to {TO_EMAIL} with {len(anomalies)} anomalies.")
        except Exception as e:
            st.error(f"Failed to send email: {e}")
    else:
        st.info("✅ No anomalies detected.")
