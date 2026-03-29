"""Anomaly detection pipeline (same behavior as the former Streamlit app)."""
import os
import smtplib
import tempfile
import threading
import time
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sqlalchemy import create_engine

# Project root (parent of WebFrontend/)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv

    load_dotenv(_PROJECT_ROOT / ".env")
except ImportError:
    pass

# Default: SQLite file on disk — no PostgreSQL install required. Override with DATABASE_URL for Postgres.
_DEFAULT_DB_PATH = _PROJECT_ROOT / "login_anomalies.db"
_DEFAULT_SQLITE_URL = f"sqlite:///{_DEFAULT_DB_PATH.resolve().as_posix()}"

_PLACEHOLDER_EMAIL = "xxxxxxxxxx@gmail.com"
_PLACEHOLDER_PASSWORD = "xxxxxxxxxxxxxxxx"

EMAIL_ADDRESS = (os.environ.get("EMAIL_ADDRESS") or _PLACEHOLDER_EMAIL).strip()
# Gmail app passwords are 16 chars; spaces in .env are optional — strip for SMTP login
EMAIL_PASSWORD = (os.environ.get("EMAIL_PASSWORD") or _PLACEHOLDER_PASSWORD).replace(" ", "").strip()
TO_EMAIL = (os.environ.get("TO_EMAIL") or "vjkarthiabi@gmail.com").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", _DEFAULT_SQLITE_URL)

# Rate-limit live login anomaly emails (many rapid attempts in a pen test)
LIVE_EMAIL_COOLDOWN_SEC = float(os.environ.get("LIVE_EMAIL_COOLDOWN_SEC", "120"))
_live_email_lock = threading.Lock()
_live_last_email_monotonic: float = 0.0


def _smtp_credentials_configured() -> bool:
    """Gmail needs a real address + App Password (not the repo placeholders)."""
    if EMAIL_ADDRESS.strip() == _PLACEHOLDER_EMAIL or "xxxx" in EMAIL_ADDRESS.lower():
        return False
    if EMAIL_PASSWORD.strip() == _PLACEHOLDER_PASSWORD or len(EMAIL_PASSWORD.strip()) < 8:
        return False
    return "@" in EMAIL_ADDRESS


def _send_anomaly_email(anomalies: pd.DataFrame, csv_path: str) -> str:
    html_table = anomalies.to_html(index=False)
    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = TO_EMAIL
    msg["Subject"] = "Login Anomaly Alert"
    body = f"""
    <h2>Login Anomaly Alert</h2>
    <p>Detected {len(anomalies)} unusual login attempts.</p>
    {html_table}
    """
    msg.attach(MIMEText(body, "html"))
    with open(csv_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", "attachment; filename=anomalies.csv")
        msg.attach(part)
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    server.send_message(msg)
    server.quit()
    return f"Email sent to {TO_EMAIL} with {len(anomalies)} anomalies."


def _live_row_for_storage(ev: dict[str, Any]) -> dict[str, Any]:
    """Align with batch CSV rows appended to login_anomalies."""
    return {
        "user_id": ev.get("user_id"),
        "timestamp": ev.get("timestamp"),
        "activity_type": "login",
        "location": ev.get("location"),
        "ip_address": ev.get("ip_address"),
        "location_encoded": None,
        "ip_encoded": None,
        "anomaly_flag": ev.get("anomaly_flag"),
        "anomaly_score": ev.get("anomaly_score"),
        "insertion_time": datetime.utcnow(),
    }


def persist_live_anomaly_event(ev: dict[str, Any]) -> dict[str, str | None]:
    """
    Persist a single real-time login anomaly and optionally email (cooldown between sends).
    ev: payload from RealtimeThreatEngine.to_dict() with anomaly_flag == 1.
    Returns db_status / email_status strings for API responses.
    """
    global _live_last_email_monotonic
    out: dict[str, str | None] = {"db_status": None, "email_status": None}
    try:
        df = pd.DataFrame([_live_row_for_storage(ev)])
        eng = create_engine(DATABASE_URL)
        df.to_sql("login_anomalies", eng, if_exists="append", index=False)
        out["db_status"] = "Anomaly saved to the database."
    except Exception as e:
        out["db_status"] = f"Database error: {e}"

    skip = os.environ.get("SKIP_EMAIL", "").strip().lower() in ("1", "true", "yes")
    if skip:
        out["email_status"] = "Email skipped (SKIP_EMAIL=1)."
        return out
    if not _smtp_credentials_configured():
        out["email_status"] = (
            "Email not sent: configure EMAIL_ADDRESS and EMAIL_PASSWORD in .env for alerts."
        )
        return out

    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        pd.DataFrame([_live_row_for_storage(ev)]).to_csv(tmp.name, index=False)
        csv_path = tmp.name
    try:
        with _live_email_lock:
            now = time.monotonic()
            if now - _live_last_email_monotonic < LIVE_EMAIL_COOLDOWN_SEC:
                wait = int(LIVE_EMAIL_COOLDOWN_SEC - (now - _live_last_email_monotonic))
                out["email_status"] = (
                    f"Email not sent (cooldown: next alert allowed in ~{wait}s)."
                )
                return out
            try:
                single = pd.DataFrame([_live_row_for_storage(ev)])
                _send_anomaly_email(single, csv_path)
                _live_last_email_monotonic = time.monotonic()
                out["email_status"] = f"Alert email sent to {TO_EMAIL}."
            except Exception as e:
                out["email_status"] = f"Email error: {e}"
    finally:
        try:
            os.unlink(csv_path)
        except OSError:
            pass
    return out


def process_csv(file_obj) -> dict[str, Any]:
    """
    file_obj: Werkzeug FileStorage or file-like with read().
    Returns keys: ok, error, total_logins, anomaly_count, columns, rows, chart,
                  db_status, email_status
    """
    try:
        df = pd.read_csv(file_obj)
    except Exception as e:
        return {"ok": False, "error": f"Could not read CSV: {e}"}

    if "activity_type" not in df.columns:
        return {"ok": False, "error": "Missing required column: 'activity_type'"}

    df = df[df["activity_type"].str.lower() == "login"].reset_index(drop=True)
    if df.empty:
        return {"ok": False, "error": "No login records found in the uploaded file."}

    if "location" not in df.columns:
        return {"ok": False, "error": "Missing required column: 'location'"}

    if "ip_address" not in df.columns:
        return {"ok": False, "error": "Missing required column: 'ip_address'"}

    encoder_loc = LabelEncoder()
    encoder_ip = LabelEncoder()
    df["location_encoded"] = encoder_loc.fit_transform(df["location"].astype(str))
    df["ip_encoded"] = encoder_ip.fit_transform(df["ip_address"].astype(str))

    X = df[["location_encoded", "ip_encoded"]]
    model = IsolationForest(contamination=0.01, random_state=42)
    df["anomaly_flag"] = pd.Series(model.fit_predict(X)).map({1: 0, -1: 1})
    df["anomaly_score"] = model.decision_function(X)

    anomalies = df[df["anomaly_flag"] == 1]

    display_df = df.copy()
    for col in display_df.columns:
        if pd.api.types.is_datetime64_any_dtype(display_df[col]):
            display_df[col] = display_df[col].astype(str)

    columns = [str(c) for c in display_df.columns]
    rows: list[dict[str, Any]] = []
    for _, row in display_df.iterrows():
        rows.append(
            {
                "cells": ["" if pd.isna(row[c]) else str(row[c]) for c in display_df.columns],
                "is_anomaly": bool(row["anomaly_flag"] == 1),
            }
        )

    chart: dict[str, Any] | None = None
    if "timestamp" in df.columns and not anomalies.empty:
        try:
            ts = pd.to_datetime(anomalies["timestamp"], errors="coerce")
            valid = anomalies.assign(_ts=ts).dropna(subset=["_ts"])
            if not valid.empty:
                g = (
                    valid.sort_values("_ts")
                    .loc[:, ["_ts", "anomaly_score", "location", "ip_address", "user_id"]]
                    .copy()
                )
                # IsolationForest anomaly scores are usually negative for anomalies.
                # Plot severity as positive magnitude so bar heights are intuitive.
                g["severity"] = g["anomaly_score"].astype(float).abs()
                chart = {
                    "labels": [t.strftime("%d %b %H:%M") for t in g["_ts"]],
                    "timestamps": [t.strftime("%Y-%m-%d %H:%M:%S") for t in g["_ts"]],
                    "values": [round(float(x), 6) for x in g["severity"]],
                    "raw_scores": [round(float(x), 6) for x in g["anomaly_score"]],
                    "locations": [str(x) for x in g["location"]],
                    "ips": [str(x) for x in g["ip_address"]],
                    "users": [str(x) for x in g["user_id"]],
                }
        except Exception:
            chart = None

    db_status: str | None = None
    email_status: str | None = None

    if not anomalies.empty:
        try:
            anomalies_out = anomalies.copy()
            anomalies_out["insertion_time"] = datetime.utcnow()
            engine = create_engine(DATABASE_URL)
            anomalies_out.to_sql("login_anomalies", engine, if_exists="append", index=False)
            db_status = "Anomaly data saved to the database."
        except Exception as e:
            db_status = f"Database error: {e}"

        skip = os.environ.get("SKIP_EMAIL", "").strip().lower() in ("1", "true", "yes")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            anomalies.to_csv(tmp.name, index=False)
            csv_path = tmp.name
        try:
            if skip:
                email_status = (
                    "Email skipped (SKIP_EMAIL=1). Remove it to enable SMTP when credentials are set."
                )
            elif not _smtp_credentials_configured():
                email_status = (
                    "Email not sent: create a project file named .env in the project root with "
                    "EMAIL_ADDRESS and EMAIL_PASSWORD. Gmail requires an App Password "
                    "(Google Account - Security - 2-Step Verification - App passwords), not your normal login password."
                )
            else:
                try:
                    email_status = _send_anomaly_email(anomalies, csv_path)
                except Exception as e:
                    email_status = (
                        f"Email error: {e}. "
                        "If you see 535 BadCredentials: use a Gmail App Password and enable 2-Step Verification."
                    )
        finally:
            try:
                os.unlink(csv_path)
            except OSError:
                pass
    else:
        db_status = None
        email_status = None

    return {
        "ok": True,
        "error": None,
        "total_logins": len(df),
        "anomaly_count": len(anomalies),
        "columns": columns,
        "rows": rows,
        "chart": chart,
        "db_status": db_status,
        "email_status": email_status,
        "no_anomalies_message": "No anomalies detected." if anomalies.empty else None,
    }
