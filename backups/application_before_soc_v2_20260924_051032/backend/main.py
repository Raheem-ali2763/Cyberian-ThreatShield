import json
import re
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = PROJECT_ROOT / "application"
FRONTEND = APP_ROOT / "frontend"
DATABASE = APP_ROOT / "data" / "threatshield.db"

APP_ROOT.mkdir(exist_ok=True)
DATABASE.parent.mkdir(exist_ok=True)

DATABASE_URL = f"sqlite:///{DATABASE}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    event_id = Column(String)
    provider = Column(String)
    timestamp = Column(String)
    computer = Column(String)
    channel = Column(String)
    image = Column(String)
    command_line = Column(Text)
    parent_image = Column(String)
    parent_command_line = Column(Text)
    user = Column(String)
    raw_event = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    rule_name = Column(String)
    severity = Column(String)
    technique = Column(String)
    description = Column(Text)
    event_id = Column(Integer)
    status = Column(String, default="NEW")
    evidence = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="Cyberian ThreatShield",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ======================================================
# HELPERS
# ======================================================

def safe(value):
    if value is None:
        return ""
    return str(value)


def create_event(db, data, raw_event=None):
    ed = data.get("event_data", {})

    event = Event(
        event_id=safe(data.get("event_id")),
        provider=safe(data.get("provider")),
        timestamp=safe(
            data.get("timestamp") or ed.get("UtcTime")
        ),
        computer=safe(data.get("computer")),
        channel=safe(data.get("channel")),
        image=safe(ed.get("Image")),
        command_line=safe(ed.get("CommandLine")),
        parent_image=safe(ed.get("ParentImage")),
        parent_command_line=safe(ed.get("ParentCommandLine")),
        user=safe(ed.get("User")),
        raw_event=raw_event or json.dumps(data)
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event


def run_detections(db, event):
    image = event.image.lower()
    command = event.command_line.lower()
    parent = event.parent_image.lower()

    detections = []

    # --------------------------------------------------
    # T1218.005 - MSHTA
    # --------------------------------------------------

    if image.endswith("\\mshta.exe") or image.endswith("/mshta.exe"):
        detections.append({
            "rule": "Suspicious MSHTA Execution",
            "severity": "MEDIUM",
            "technique": "T1218.005",
            "description": "MSHTA process execution detected.",
        })

    # --------------------------------------------------
    # T1218.011 - RUNDLL32
    # --------------------------------------------------

    if image.endswith("\\rundll32.exe") or image.endswith("/rundll32.exe"):
        detections.append({
            "rule": "Suspicious Rundll32 Execution",
            "severity": "MEDIUM",
            "technique": "T1218.011",
            "description": "Rundll32 process execution detected.",
        })

    # --------------------------------------------------
    # MSHTA -> RUNDLL32 CORRELATION
    # --------------------------------------------------

    if (
        image.endswith("\\rundll32.exe")
        and (
            parent.endswith("\\mshta.exe")
            or parent.endswith("/mshta.exe")
        )
    ):
        detections.append({
            "rule": "MSHTA to Rundll32 Process Chain",
            "severity": "HIGH",
            "technique": "T1218.005 / T1218.011",
            "description": "Rundll32 execution observed with MSHTA as parent.",
        })

    # --------------------------------------------------
    # T1059.003 - CMD
    # --------------------------------------------------

    if image.endswith("\\cmd.exe") or image.endswith("/cmd.exe"):
        detections.append({
            "rule": "Windows Command Shell Execution",
            "severity": "LOW",
            "technique": "T1059.003",
            "description": "Windows command shell execution detected.",
        })

    # --------------------------------------------------
    # Store alerts
    # --------------------------------------------------

    for detection in detections:

        alert = Alert(
            rule_name=detection["rule"],
            severity=detection["severity"],
            technique=detection["technique"],
            description=detection["description"],
            event_id=event.id,
            status="NEW",
            evidence=json.dumps({
                "event_id": event.event_id,
                "image": event.image,
                "command_line": event.command_line,
                "parent_image": event.parent_image,
                "user": event.user,
                "computer": event.computer
            })
        )

        db.add(alert)

    if detections:
        db.commit()

    return detections


# ======================================================
# API
# ======================================================

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "application": "Cyberian ThreatShield",
        "version": "1.0.0"
    }


@app.get("/api/stats")
def stats():

    db = SessionLocal()

    try:
        events = db.query(Event).count()
        alerts = db.query(Alert).count()

        high = db.query(Alert).filter(
            Alert.severity == "HIGH"
        ).count()

        medium = db.query(Alert).filter(
            Alert.severity == "MEDIUM"
        ).count()

        low = db.query(Alert).filter(
            Alert.severity == "LOW"
        ).count()

        sigma_dir = PROJECT_ROOT / "02-detection-rules"
        sigma_count = len(
            list(sigma_dir.rglob("*.yml"))
        ) if sigma_dir.exists() else 0

        return {
            "events": events,
            "alerts": alerts,
            "high": high,
            "medium": medium,
            "low": low,
            "sigma_rules": sigma_count,
            "hunts": 2,
            "incidents": 2,
            "playbooks": 3
        }

    finally:
        db.close()


@app.get("/api/events")
def get_events(limit: int = 100):

    db = SessionLocal()

    try:
        rows = (
            db.query(Event)
            .order_by(Event.id.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": e.id,
                "event_id": e.event_id,
                "provider": e.provider,
                "timestamp": e.timestamp,
                "computer": e.computer,
                "image": e.image,
                "command_line": e.command_line,
                "parent_image": e.parent_image,
                "user": e.user
            }
            for e in rows
        ]

    finally:
        db.close()


@app.get("/api/alerts")
def get_alerts(limit: int = 100):

    db = SessionLocal()

    try:
        rows = (
            db.query(Alert)
            .order_by(Alert.id.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": a.id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "technique": a.technique,
                "description": a.description,
                "event_id": a.event_id,
                "status": a.status,
                "created_at": str(a.created_at)
            }
            for a in rows
        ]

    finally:
        db.close()


@app.post("/api/ingest/jsonl")
async def ingest_jsonl(file: UploadFile = File(...)):

    db = SessionLocal()

    total = 0
    detections = 0

    try:

        content = await file.read()

        for line in content.decode(
            "utf-8",
            errors="replace"
        ).splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = create_event(
                db,
                data,
                raw_event=line
            )

            matches = run_detections(
                db,
                event
            )

            total += 1
            detections += len(matches)

        return {
            "status": "success",
            "events_ingested": total,
            "detections_created": detections
        }

    finally:
        db.close()


@app.post("/api/ingest/current-sample")
def ingest_current_sample():

    sample = (
        PROJECT_ROOT
        / "datasets"
        / "processed"
        / "maldoc_mshta_sample.jsonl"
    )

    if not sample.exists():
        return {
            "status": "error",
            "message": "Current sample not found."
        }

    db = SessionLocal()

    total = 0
    detections = 0

    try:

        for line in sample.read_text(
            encoding="utf-8"
        ).splitlines():

            if not line.strip():
                continue

            data = json.loads(line)

            event = create_event(
                db,
                data,
                raw_event=line
            )

            matches = run_detections(
                db,
                event
            )

            total += 1
            detections += len(matches)

        return {
            "status": "success",
            "source": str(sample),
            "events_ingested": total,
            "detections_created": detections
        }

    finally:
        db.close()


@app.post("/api/alerts/{alert_id}/close")
def close_alert(alert_id: int):

    db = SessionLocal()

    try:

        alert = (
            db.query(Alert)
            .filter(Alert.id == alert_id)
            .first()
        )

        if not alert:
            return {
                "status": "error",
                "message": "Alert not found"
            }

        alert.status = "CLOSED"
        db.commit()

        return {
            "status": "success",
            "alert_id": alert_id,
            "new_status": "CLOSED"
        }

    finally:
        db.close()


@app.get("/")
def dashboard():
    return FileResponse(
        FRONTEND / "index.html"
    )
