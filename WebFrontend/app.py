"""Flask web UI: batch CSV analysis + realtime threat monitor (WebSockets)."""
import os
import threading
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

from anomaly_core import persist_live_anomaly_event, process_csv
from realtime_detector import RealtimeThreatEngine, random_demo_event

_ROOT = Path(__file__).resolve().parent
_PROJECT_ROOT = _ROOT.parent

app = Flask(
    __name__,
    template_folder=str(_ROOT / "templates"),
    static_folder=str(_ROOT / "static"),
)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
app.config["SECRET_KEY"] = __name__ + "-anomaly-soc"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    logger=False,
    engineio_logger=False,
)

engine = RealtimeThreatEngine()
BASELINE_CSV = _PROJECT_ROOT / "sample_login_events.csv"
_fit_result: dict | None = None
_demo_stream_started = False
_demo_lock = threading.Lock()


def _client_ip() -> str:
    """Best-effort client IP (honor reverse-proxy headers when present)."""
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP", "").strip()
    if xri:
        return xri.split(",")[0].strip()
    return (request.remote_addr or "127.0.0.1").strip()


def _ensure_engine() -> dict:
    global _fit_result
    if _fit_result is None:
        _fit_result = engine.fit_from_csv(BASELINE_CSV)
    return _fit_result


@socketio.on("connect")
def _on_connect():
    _ensure_engine()
    socketio.emit("soc_status", {"connected": True, "fit": _fit_result})


@socketio.on("start_demo")
def _on_start_demo():
    """Client requests demo stream; idempotent — one background producer."""
    global _demo_stream_started
    _ensure_engine()
    with _demo_lock:
        if _demo_stream_started:
            return
        _demo_stream_started = True
    socketio.start_background_task(_demo_stream_loop)


def _demo_stream_loop():
    import time

    _ensure_engine()
    while True:
        socketio.sleep(1.2 + (time.time() % 0.4))
        uid, loc, ip, tag = random_demo_event()
        try:
            ev = engine.score(loc, ip, user_id=uid, source=tag)
            socketio.emit("threat_event", engine.to_dict(ev))
            socketio.emit(
                "stats_update",
                {
                    "total_events": engine.stats.total_events,
                    "threats_total": engine.stats.threats_total,
                    "threats_last_120s": engine.stats.threats_last_window,
                    "last": engine.stats.last_event,
                },
            )
        except Exception as e:
            socketio.emit("stream_error", {"error": str(e)})


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    f = request.files.get("csv_file")
    if not f or f.filename == "":
        return render_template(
            "index.html",
            error="Please choose a CSV file to upload.",
        )

    if not f.filename.lower().endswith(".csv"):
        return render_template(
            "index.html",
            error="Only .csv files are supported.",
        )

    result = process_csv(f.stream)
    if not result["ok"]:
        return render_template("index.html", error=result.get("error", "Unknown error."))

    return render_template("results.html", result=result)


@app.route("/live")
def live_monitor():
    fit = _ensure_engine()
    return render_template("threat_monitor.html", fit=fit)


@app.route("/login", methods=["GET"])
def login_page():
    fit = _ensure_engine()
    return render_template("login.html", fit=fit, client_ip=_client_ip())


@app.route("/api/login", methods=["POST"])
def api_login():
    """Score a login attempt using server-derived IP + user location; broadcast + persist anomalies."""
    _ensure_engine()
    data = request.get_json(silent=True) or {}
    loc = (data.get("location") or data.get("Location") or "").strip()
    user = (data.get("username") or data.get("user_id") or "guest").strip() or "guest"
    if not loc:
        return jsonify({"ok": False, "error": "location is required"}), 400
    ip = _client_ip()
    try:
        ev = engine.score(str(loc), str(ip), user_id=str(user), source="login_page")
        payload = engine.to_dict(ev)
        socketio.emit("threat_event", payload)
        socketio.emit(
            "stats_update",
            {
                "total_events": engine.stats.total_events,
                "threats_total": engine.stats.threats_total,
                "threats_last_120s": engine.stats.threats_last_window,
                "last": engine.stats.last_event,
            },
        )
        persist_info: dict | None = None
        if ev.anomaly_flag:
            persist_info = persist_live_anomaly_event(payload)
        body: dict = {"ok": True, "event": payload, "client_ip": ip}
        if persist_info:
            body["db_status"] = persist_info.get("db_status")
            body["email_status"] = persist_info.get("email_status")
        return jsonify(body)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Ingest a single login event (JSON) — for integrations / manual tests."""
    _ensure_engine()
    data = request.get_json(silent=True) or {}
    loc = data.get("location") or data.get("Location")
    ip = data.get("ip_address") or data.get("ip") or data.get("IP")
    uid = data.get("user_id", "api")
    if not loc or not ip:
        return jsonify({"ok": False, "error": "JSON needs location and ip_address"}), 400
    try:
        ev = engine.score(str(loc), str(ip), user_id=str(uid), source="api")
        payload = engine.to_dict(ev)
        socketio.emit("threat_event", payload)
        socketio.emit(
            "stats_update",
            {
                "total_events": engine.stats.total_events,
                "threats_total": engine.stats.threats_total,
                "threats_last_120s": engine.stats.threats_last_window,
                "last": engine.stats.last_event,
            },
        )
        return jsonify({"ok": True, "event": payload})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/threat-status")
def threat_status():
    _ensure_engine()
    return jsonify(
        {
            "fit": _fit_result,
            "total_events": engine.stats.total_events,
            "threats_total": engine.stats.threats_total,
            "threats_last_120s": engine.stats.threats_last_window,
            "last": engine.stats.last_event,
        }
    )


if __name__ == "__main__":
    _ensure_engine()
    # Default 5000 — not 8501 (Streamlit’s default), so both can run. Override: set FLASK_PORT=5050
    _port = int(os.environ.get("FLASK_PORT", "5000"))
    socketio.run(app, host="127.0.0.1", port=_port, debug=True, allow_unsafe_werkzeug=True)
