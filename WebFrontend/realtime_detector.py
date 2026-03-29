"""
Stateful Isolation Forest scorer for live login events.
Fits on baseline CSV; new location/IP tokens extend the encoding (novelty-friendly).
"""
from __future__ import annotations

import random
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

_LOCK = threading.Lock()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _threat_level(anomaly_flag: int, score: float) -> str:
    if not anomaly_flag:
        return "NORMAL"
    # Lower decision_function = more anomalous for isolation forest
    if score < -0.02:
        return "CRITICAL"
    if score < 0:
        return "HIGH"
    return "ELEVATED"


def _risk_score(anomaly_flag: int, score: float) -> int:
    """0-100 heuristic for dashboard gauges."""
    if not anomaly_flag:
        return max(0, min(100, int(55 + score * 120)))
    base = 72
    base += int(max(0, -score * 400))
    return min(100, base)


@dataclass
class ThreatEvent:
    event_id: str
    ts_iso: str
    user_id: str
    location: str
    ip_address: str
    anomaly_flag: int
    anomaly_score: float
    threat_level: str
    risk_score: int
    source: str  # "stream" | "api" | "manual"


@dataclass
class ThreatStats:
    total_events: int = 0
    threats_total: int = 0
    threats_last_window: int = 0
    last_event: dict[str, Any] | None = None
    recent_threat_times: deque = field(default_factory=lambda: deque(maxlen=500))

    def record(self, ev: ThreatEvent, window_sec: int = 120) -> None:
        self.total_events += 1
        if ev.anomaly_flag:
            self.threats_total += 1
            self.recent_threat_times.append(_utc_now().timestamp())
        self.last_event = {
            "event_id": ev.event_id,
            "ts": ev.ts_iso,
            "user_id": ev.user_id,
            "location": ev.location,
            "ip_address": ev.ip_address,
            "anomaly_flag": ev.anomaly_flag,
            "anomaly_score": ev.anomaly_score,
            "threat_level": ev.threat_level,
            "risk_score": ev.risk_score,
            "source": ev.source,
        }
        cutoff = _utc_now().timestamp() - window_sec
        while self.recent_threat_times and self.recent_threat_times[0] < cutoff:
            self.recent_threat_times.popleft()
        self.threats_last_window = len(self.recent_threat_times)


class RealtimeThreatEngine:
    """Train once on baseline logins; score single events in microseconds."""

    def __init__(self) -> None:
        self._loc: dict[str, int] = {}
        self._ip: dict[str, int] = {}
        self._model: IsolationForest | None = None
        self._fitted = False
        self.stats = ThreatStats()

    def _token(self, table: dict[str, int], value: str) -> int:
        v = str(value).strip()
        if v not in table:
            table[v] = len(table)
        return table[v]

    def fit_from_csv(self, path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {"ok": False, "error": f"Baseline CSV not found: {path}"}
        df = pd.read_csv(path)
        if "activity_type" not in df.columns:
            return {"ok": False, "error": "CSV must include activity_type"}
        df = df[df["activity_type"].str.lower() == "login"].copy()
        if df.empty:
            return {"ok": False, "error": "No login rows in baseline CSV"}
        if not {"location", "ip_address"}.issubset(df.columns):
            return {"ok": False, "error": "Baseline CSV needs location and ip_address"}

        self._loc.clear()
        self._ip.clear()
        rows = []
        for _, row in df.iterrows():
            li = self._token(self._loc, str(row["location"]))
            ii = self._token(self._ip, str(row["ip_address"]))
            rows.append([li, ii])
        X = np.asarray(rows, dtype=np.float64)
        self._model = IsolationForest(contamination=0.01, random_state=42, n_estimators=200)
        self._model.fit(X)
        self._fitted = True
        return {
            "ok": True,
            "baseline_rows": len(df),
            "locations": len(self._loc),
            "ips": len(self._ip),
        }

    def score(
        self,
        location: str,
        ip_address: str,
        user_id: str = "unknown",
        source: str = "api",
    ) -> ThreatEvent:
        if not self._fitted or self._model is None:
            raise RuntimeError("Engine not fitted — add sample_login_events.csv and restart.")

        li = self._token(self._loc, location)
        ii = self._token(self._ip, ip_address)
        X = np.array([[li, ii]], dtype=np.float64)
        pred = self._model.predict(X)[0]
        score = float(self._model.decision_function(X)[0])
        flag = 1 if pred == -1 else 0
        level = _threat_level(flag, score)
        risk = _risk_score(flag, score)
        now = _utc_now()
        ev = ThreatEvent(
            event_id=str(uuid.uuid4())[:8],
            ts_iso=now.isoformat(),
            user_id=str(user_id),
            location=str(location),
            ip_address=str(ip_address),
            anomaly_flag=flag,
            anomaly_score=score,
            threat_level=level,
            risk_score=risk,
            source=source,
        )
        with _LOCK:
            self.stats.record(ev)
        return ev

    def to_dict(self, ev: ThreatEvent) -> dict[str, Any]:
        return {
            "event_id": ev.event_id,
            "timestamp": ev.ts_iso,
            "user_id": ev.user_id,
            "location": ev.location,
            "ip_address": ev.ip_address,
            "anomaly_flag": ev.anomaly_flag,
            "anomaly_score": round(ev.anomaly_score, 6),
            "threat_level": ev.threat_level,
            "risk_score": ev.risk_score,
            "source": ev.source,
        }


# --- Demo stream: realistic Indian corporate logins + injected outliers ---
_NORMAL_LOCATIONS = [
    "Mumbai",
    "Bengaluru",
    "Chennai",
    "Hyderabad",
    "Pune",
    "Ahmedabad",
    "Kolkata",
    "Kochi",
]
_NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 80)]
_SUSPICIOUS_IPS = ["45.142.192.14", "185.220.101.41", "103.152.112.8", "198.51.100.77"]
_RARE_LOCATIONS = ["Port Blair", "Leh", "Itanagar", "Kohima", "Dibrugarh"]


def random_demo_event() -> tuple[str, str, str, str]:
    """Returns (user_id, location, ip, source_tag)."""
    uid = str(random.randint(1, 120))
    # Inject ~12% high-signal outliers
    if random.random() < 0.12:
        loc = random.choice(_RARE_LOCATIONS)
        ip = random.choice(_SUSPICIOUS_IPS + _NORMAL_IPS)
        return uid, loc, ip, "stream"
    loc = random.choice(_NORMAL_LOCATIONS)
    ip = random.choice(_NORMAL_IPS)
    return uid, loc, ip, "stream"
