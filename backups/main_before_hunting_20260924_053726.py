from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from pathlib import Path
from datetime import datetime
import json
import re
import asyncio

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"

DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "threatshield.db"

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


# ============================================================
# DATABASE MODELS
# ============================================================

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    event_id = Column(String)
    provider = Column(String)
    channel = Column(String)
    image = Column(String)
    command_line = Column(Text)
    parent_image = Column(String)
    parent_command_line = Column(Text)
    user = Column(String)
    timestamp = Column(String)
    raw_json = Column(Text)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    title = Column(String)
    severity = Column(String)
    technique = Column(String)
    technique_name = Column(String)
    description = Column(Text)
    source_event_id = Column(Integer)
    status = Column(String, default="OPEN")
    created_at = Column(String)


Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Cyberian ThreatShield",
    version="2.0",
    description="Detection Engineering & Threat Hunting SOC Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HELPERS
# ============================================================

def basename(path):
    if not path:
        return ""
    return path.replace("\\", "/").split("/")[-1].lower()


def create_alert(
    db,
    title,
    severity,
    technique,
    technique_name,
    description,
    event_id
):
    alert = Alert(
        title=title,
        severity=severity,
        technique=technique,
        technique_name=technique_name,
        description=description,
        source_event_id=event_id,
        status="OPEN",
        created_at=datetime.utcnow().isoformat()
    )

    db.add(alert)
    return alert


def run_detection(db, event):
    image = basename(event.image)
    parent = basename(event.parent_image)
    command = (event.command_line or "").lower()

    # --------------------------------------------------------
    # MSHTA
    # --------------------------------------------------------

    if image == "mshta.exe":
        create_alert(
            db,
            "Suspicious MSHTA Execution",
            "MEDIUM",
            "T1218.005",
            "Mshta",
            "MSHTA process execution detected in process creation telemetry.",
            event.id
        )

    # --------------------------------------------------------
    # RUNDLL32
    # --------------------------------------------------------

    if image == "rundll32.exe":
        create_alert(
            db,
            "Suspicious Rundll32 Execution",
            "MEDIUM",
            "T1218.011",
            "Rundll32",
            "Rundll32 execution detected. Review DLL and command-line activity.",
            event.id
        )

    # --------------------------------------------------------
    # MSHTA -> RUNDLL32 CORRELATION
    # --------------------------------------------------------

    if image == "rundll32.exe" and parent == "mshta.exe":
        create_alert(
            db,
            "MSHTA → RUNDLL32 Process Chain",
            "HIGH",
            "T1218",
            "System Binary Proxy Execution",
            "Rundll32 was spawned by MSHTA, matching a suspicious LOLBin process chain.",
            event.id
        )

    # --------------------------------------------------------
    # CMD
    # --------------------------------------------------------

    if image == "cmd.exe":
        create_alert(
            db,
            "Command Shell Activity",
            "LOW",
            "T1059.003",
            "Windows Command Shell",
            "Windows command shell execution detected.",
            event.id
        )

    # --------------------------------------------------------
    # POWERSHELL
    # --------------------------------------------------------

    if image == "powershell.exe" or image == "pwsh.exe":
        create_alert(
            db,
            "PowerShell Execution",
            "MEDIUM",
            "T1059.001",
            "PowerShell",
            "PowerShell process execution detected.",
            event.id
        )

    # --------------------------------------------------------
    # SCRIPTING
    # --------------------------------------------------------

    if image in ["wscript.exe", "cscript.exe"]:
        create_alert(
            db,
            "Windows Script Host Execution",
            "MEDIUM",
            "T1059.005",
            "Visual Basic",
            "Windows Script Host activity detected.",
            event.id
        )

    # --------------------------------------------------------
    # REGSVR32
    # --------------------------------------------------------

    if image == "regsvr32.exe":
        create_alert(
            db,
            "Regsvr32 Execution",
            "MEDIUM",
            "T1218.010",
            "Regsvr32",
            "Regsvr32 execution detected.",
            event.id
        )

    # --------------------------------------------------------
    # CERTUTIL
    # --------------------------------------------------------

    if image == "certutil.exe":
        create_alert(
            db,
            "Certutil Activity",
            "MEDIUM",
            "T1140",
            "Deobfuscate/Decode Files",
            "Certutil activity detected.",
            event.id
        )

    # --------------------------------------------------------
    # WMIC
    # --------------------------------------------------------

    if image == "wmic.exe":
        create_alert(
            db,
            "WMIC Activity",
            "MEDIUM",
            "T1047",
            "Windows Management Instrumentation",
            "WMIC execution detected.",
            event.id
        )

    # --------------------------------------------------------
    # SCHEDULED TASK
    # --------------------------------------------------------

    if image == "schtasks.exe":
        create_alert(
            db,
            "Scheduled Task Activity",
            "MEDIUM",
            "T1053.005",
            "Scheduled Task",
            "Scheduled task utility execution detected.",
            event.id
        )


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def dashboard():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "Cyberian ThreatShield",
        "version": "2.0"
    }


@app.get("/api/stats")
def stats():
    db = SessionLocal()

    try:
        events = db.query(Event).count()
        alerts = db.query(Alert).count()
        high = db.query(Alert).filter(Alert.severity == "HIGH").count()
        medium = db.query(Alert).filter(Alert.severity == "MEDIUM").count()
        low = db.query(Alert).filter(Alert.severity == "LOW").count()

        return {
            "events": events,
            "alerts": alerts,
            "high": high,
            "medium": medium,
            "low": low,
            "sigma_rules": 19
        }

    finally:
        db.close()


@app.get("/api/events")
def events(limit: int = 100):
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
                "id": x.id,
                "event_id": x.event_id,
                "provider": x.provider,
                "channel": x.channel,
                "image": x.image,
                "command_line": x.command_line,
                "parent_image": x.parent_image,
                "parent_command_line": x.parent_command_line,
                "user": x.user,
                "timestamp": x.timestamp
            }
            for x in rows
        ]

    finally:
        db.close()


@app.get("/api/alerts")
def alerts(limit: int = 100):
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
                "id": x.id,
                "title": x.title,
                "severity": x.severity,
                "technique": x.technique,
                "technique_name": x.technique_name,
                "description": x.description,
                "source_event_id": x.source_event_id,
                "status": x.status,
                "created_at": x.created_at
            }
            for x in rows
        ]

    finally:
        db.close()


@app.get("/api/incidents")
def incidents():
    db = SessionLocal()

    try:
        high = db.query(Alert).filter(Alert.severity == "HIGH").count()
        medium = db.query(Alert).filter(Alert.severity == "MEDIUM").count()

        return [
            {
                "id": "INC-001",
                "title": "MSHTA → RUNDLL32 Suspicious Chain",
                "severity": "HIGH",
                "status": "OPEN",
                "alerts": high,
                "description": "Potential LOLBin execution chain requiring investigation."
            },
            {
                "id": "INC-002",
                "title": "Suspicious Script Interpreter Activity",
                "severity": "MEDIUM",
                "status": "OPEN",
                "alerts": medium,
                "description": "Script interpreter activity observed in telemetry."
            }
        ]

    finally:
        db.close()


@app.get("/api/mitre")
def mitre():
    db = SessionLocal()

    try:
        rows = db.query(Alert).all()

        techniques = {}

        for x in rows:
            if x.technique not in techniques:
                techniques[x.technique] = {
                    "id": x.technique,
                    "name": x.technique_name,
                    "count": 0,
                    "severity": x.severity
                }

            techniques[x.technique]["count"] += 1

        return list(techniques.values())

    finally:
        db.close()


@app.get("/api/hunts")
def hunts():
    return [
        {
            "id": "HUNT-01",
            "title": "Suspicious Script Interpreter Chains",
            "status": "COMPLETED",
            "finding": "WINWORD → MSHTA → RUNDLL32 observed in sample telemetry."
        },
        {
            "id": "HUNT-02",
            "title": "Suspicious Command Interpreter Activity",
            "status": "COMPLETED",
            "finding": "cmd.exe activity observed in sample telemetry."
        }
    ]


@app.get("/api/playbooks")
def playbooks():
    return [
        {
            "id": "PB-01",
            "name": "Credential Compromise",
            "status": "READY"
        },
        {
            "id": "PB-02",
            "name": "Lateral Movement",
            "status": "READY"
        },
        {
            "id": "PB-03",
            "name": "Command and Control",
            "status": "READY"
        }
    ]


@app.get("/api/iocs")
def iocs():
    return [
        {
            "type": "PROCESS",
            "value": "mshta.exe",
            "source": "EVTX telemetry",
            "status": "OBSERVED"
        },
        {
            "type": "PROCESS",
            "value": "rundll32.exe",
            "source": "EVTX telemetry",
            "status": "OBSERVED"
        },
        {
            "type": "FILE",
            "value": "C:\\Users\\Public\\memViewData.hta",
            "source": "EVTX telemetry",
            "status": "OBSERVED"
        }
    ]


@app.post("/api/alerts/{alert_id}/close")
def close_alert(alert_id: int):
    db = SessionLocal()

    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        alert.status = "CLOSED"
        db.commit()

        return {
            "status": "closed",
            "alert_id": alert_id
        }

    finally:
        db.close()


@app.post("/api/ingest/current-sample")
def ingest_current_sample():
    db = SessionLocal()

    try:
        jsonl = (
            BASE_DIR.parent
            / "datasets"
            / "processed"
            / "maldoc_mshta_sample.jsonl"
        )

        if not jsonl.exists():
            raise HTTPException(
                status_code=404,
                detail=f"Sample not found: {jsonl}"
            )

        inserted = 0

        with open(jsonl, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    data = json.loads(line)
                except Exception:
                    continue

                event = Event(
                    event_id=str(
                        data.get("EventID")
                        or data.get("event_id")
                        or ""
                    ),
                    provider=str(data.get("Provider", "")),
                    channel=str(data.get("Channel", "")),
                    image=str(data.get("Image", "")),
                    command_line=str(data.get("CommandLine", "")),
                    parent_image=str(data.get("ParentImage", "")),
                    parent_command_line=str(
                        data.get("ParentCommandLine", "")
                    ),
                    user=str(data.get("User", "")),
                    timestamp=str(
                        data.get("UtcTime")
                        or data.get("TimeCreated")
                        or ""
                    ),
                    raw_json=json.dumps(data)
                )

                db.add(event)
                db.flush()

                run_detection(db, event)

                inserted += 1

        db.commit()

        return {
            "status": "success",
            "events_ingested": inserted
        }

    finally:
        db.close()


@app.post("/api/ingest/jsonl")
def ingest_jsonl():
    return ingest_current_sample()




# ============================================================
# ALERT INVESTIGATION API
# ============================================================

@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int):
    db = SessionLocal()

    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        event = None

        if alert.source_event_id:
            event = (
                db.query(Event)
                .filter(Event.id == alert.source_event_id)
                .first()
            )

        return {
            "alert": {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "technique": alert.technique,
                "technique_name": alert.technique_name,
                "description": alert.description,
                "status": alert.status,
                "created_at": alert.created_at,
                "source_event_id": alert.source_event_id
            },
            "event": None if not event else {
                "id": event.id,
                "event_id": event.event_id,
                "provider": event.provider,
                "channel": event.channel,
                "image": event.image,
                "command_line": event.command_line,
                "parent_image": event.parent_image,
                "parent_command_line": event.parent_command_line,
                "user": event.user,
                "timestamp": event.timestamp
            }
        }

    finally:
        db.close()


@app.get("/api/alerts/{alert_id}/related")
def related_alerts(alert_id: int):
    db = SessionLocal()

    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        rows = (
            db.query(Alert)
            .filter(
                Alert.source_event_id == alert.source_event_id,
                Alert.id != alert.id
            )
            .order_by(Alert.id.desc())
            .all()
        )

        return [
            {
                "id": x.id,
                "title": x.title,
                "severity": x.severity,
                "technique": x.technique,
                "status": x.status
            }
            for x in rows
        ]

    finally:
        db.close()


@app.get("/api/investigation/{alert_id}")
def investigation(alert_id: int):
    db = SessionLocal()

    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        event = None

        if alert.source_event_id:
            event = (
                db.query(Event)
                .filter(Event.id == alert.source_event_id)
                .first()
            )

        related = (
            db.query(Alert)
            .filter(
                Alert.source_event_id == alert.source_event_id
            )
            .all()
        )

        return {
            "case": {
                "case_id": f"CASE-{alert.id:04d}",
                "alert_id": alert.id,
                "status": alert.status,
                "severity": alert.severity
            },
            "detection": {
                "title": alert.title,
                "technique": alert.technique,
                "technique_name": alert.technique_name,
                "description": alert.description
            },
            "evidence": None if not event else {
                "event_id": event.event_id,
                "provider": event.provider,
                "channel": event.channel,
                "timestamp": event.timestamp,
                "process": event.image,
                "parent_process": event.parent_image,
                "command_line": event.command_line,
                "parent_command_line": event.parent_command_line,
                "user": event.user
            },
            "related_detections": [
                {
                    "id": x.id,
                    "title": x.title,
                    "severity": x.severity,
                    "technique": x.technique
                }
                for x in related
            ],
            "assessment": (
                "Potentially suspicious execution chain. "
                "Validate process ancestry, command line, user context "
                "and surrounding telemetry before closing the case."
            )
        }

    finally:
        db.close()




# ============================================================
# INCIDENT MANAGEMENT
# ============================================================

@app.post("/api/incidents/create/{alert_id}")
def create_incident(alert_id: int):

    from datetime import datetime

    db = SessionLocal()

    try:

        alert = (
            db.query(Alert)
            .filter(Alert.id == alert_id)
            .first()
        )

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        from sqlalchemy import text

        number = f"INC-{alert_id:04d}"

        existing = db.execute(
            text("""
                SELECT id
                FROM incidents
                WHERE source_alert_id = :alert_id
            """),
            {"alert_id": alert_id}
        ).fetchone()

        if existing:

            return {
                "status": "exists",
                "incident_id": existing[0]
            }

        now = datetime.utcnow().isoformat()

        result = db.execute(
            text("""
                INSERT INTO incidents
                (
                    incident_number,
                    title,
                    severity,
                    status,
                    description,
                    source_alert_id,
                    created_at,
                    updated_at
                )
                VALUES
                (
                    :number,
                    :title,
                    :severity,
                    'OPEN',
                    :description,
                    :alert_id,
                    :created,
                    :updated
                )
            """),
            {
                "number": number,
                "title": alert.title,
                "severity": alert.severity,
                "description": alert.description,
                "alert_id": alert_id,
                "created": now,
                "updated": now
            }
        )

        db.commit()

        incident_id = result.lastrowid

        db.execute(
            text("""
                INSERT INTO incident_timeline
                (
                    incident_id,
                    action,
                    details,
                    created_at
                )
                VALUES
                (
                    :incident,
                    'INCIDENT_CREATED',
                    :details,
                    :created
                )
            """),
            {
                "incident": incident_id,
                "details": f"Incident created from alert #{alert_id}",
                "created": now
            }
        )

        db.commit()

        return {
            "status": "created",
            "incident_id": incident_id,
            "incident_number": number
        }

    finally:
        db.close()


@app.get("/api/incidents/live")
def get_live_incidents():

    from sqlalchemy import text

    db = SessionLocal()

    try:

        rows = db.execute(
            text("""
                SELECT
                    id,
                    incident_number,
                    title,
                    severity,
                    status,
                    description,
                    source_alert_id,
                    created_at,
                    updated_at
                FROM incidents
                ORDER BY id DESC
            """)
        ).fetchall()

        return [
            {
                "id": x[0],
                "incident_number": x[1],
                "title": x[2],
                "severity": x[3],
                "status": x[4],
                "description": x[5],
                "source_alert_id": x[6],
                "created_at": x[7],
                "updated_at": x[8]
            }
            for x in rows
        ]

    finally:
        db.close()


@app.post("/api/incidents/{incident_id}/status/{new_status}")
def update_incident_status(
    incident_id: int,
    new_status: str
):

    from datetime import datetime
    from sqlalchemy import text

    allowed = [
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED"
    ]

    new_status = new_status.upper()

    if new_status not in allowed:

        raise HTTPException(
            status_code=400,
            detail="Invalid incident status"
        )

    db = SessionLocal()

    try:

        now = datetime.utcnow().isoformat()

        row = db.execute(
            text("""
                SELECT incident_number
                FROM incidents
                WHERE id=:id
            """),
            {"id": incident_id}
        ).fetchone()

        if not row:

            raise HTTPException(
                status_code=404,
                detail="Incident not found"
            )

        db.execute(
            text("""
                UPDATE incidents
                SET status=:status,
                    updated_at=:updated
                WHERE id=:id
            """),
            {
                "status": new_status,
                "updated": now,
                "id": incident_id
            }
        )

        db.execute(
            text("""
                INSERT INTO incident_timeline
                (
                    incident_id,
                    action,
                    details,
                    created_at
                )
                VALUES
                (
                    :incident,
                    'STATUS_CHANGED',
                    :details,
                    :created
                )
            """),
            {
                "incident": incident_id,
                "details": f"Incident status changed to {new_status}",
                "created": now
            }
        )

        db.commit()

        return {
            "status": "updated",
            "incident_id": incident_id,
            "new_status": new_status
        }

    finally:
        db.close()


@app.get("/api/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: int):

    from sqlalchemy import text

    db = SessionLocal()

    try:

        rows = db.execute(
            text("""
                SELECT
                    id,
                    action,
                    details,
                    created_at
                FROM incident_timeline
                WHERE incident_id=:incident
                ORDER BY id DESC
            """),
            {"incident": incident_id}
        ).fetchall()

        return [
            {
                "id": x[0],
                "action": x[1],
                "details": x[2],
                "created_at": x[3]
            }
            for x in rows
        ]

    finally:
        db.close()


# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket):
    await websocket.accept()

    try:
        while True:
            db = SessionLocal()

            try:
                events_count = db.query(Event).count()
                alerts_count = db.query(Alert).count()
            finally:
                db.close()

            await websocket.send_json({
                "events": events_count,
                "alerts": alerts_count,
                "timestamp": datetime.utcnow().isoformat()
            })

            await asyncio.sleep(3)

    except Exception:
        pass
