from pathlib import Path
import sqlite3
import json
from datetime import datetime

ROOT = Path.cwd()

jsonl_files = list(
    ROOT.rglob("maldoc_mshta_sample.jsonl")
)

if not jsonl_files:
    raise SystemExit("ERROR: JSONL not found")

JSONL = jsonl_files[0]

DB = ROOT / "application" / "data" / "threatshield.db"

DB.parent.mkdir(parents=True, exist_ok=True)

print("JSONL:", JSONL)
print("DB   :", DB)

conn = sqlite3.connect(DB)
cur = conn.cursor()

# ============================================================
# TABLES
# ============================================================

cur.execute("""
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    provider TEXT,
    channel TEXT,
    image TEXT,
    command_line TEXT,
    parent_image TEXT,
    parent_command_line TEXT,
    user TEXT,
    timestamp TEXT,
    raw_json TEXT
)
""")

cur.execute("""
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    severity TEXT,
    technique TEXT,
    technique_name TEXT,
    description TEXT,
    source_event_id INTEGER,
    status TEXT,
    created_at TEXT
)
""")

# ============================================================
# HELPERS
# ============================================================

def get(data, *keys):

    for key in keys:

        if key in data:

            value = data[key]

            if value not in (None, ""):
                return str(value)

    lowered = {
        str(k).lower(): v
        for k, v in data.items()
    }

    for key in keys:

        value = lowered.get(key.lower())

        if value not in (None, ""):
            return str(value)

    return ""


def basename(value):

    if not value:
        return ""

    return value.replace("\\", "/").split("/")[-1].lower()


def create_alert(
    title,
    severity,
    technique,
    technique_name,
    description,
    event_id
):

    cur.execute("""
        INSERT INTO alerts (
            title,
            severity,
            technique,
            technique_name,
            description,
            source_event_id,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        title,
        severity,
        technique,
        technique_name,
        description,
        event_id,
        "OPEN",
        datetime.utcnow().isoformat()
    ))


# ============================================================
# READ TELEMETRY
# ============================================================

events = []

with open(JSONL, "r", errors="ignore") as f:

    for line in f:

        line = line.strip()

        if not line:
            continue

        try:
            data = json.loads(line)
        except Exception:
            continue

        event = {
            "event_id": get(
                data,
                "EventID",
                "event_id",
                "EventId"
            ),

            "provider": get(
                data,
                "Provider",
                "provider",
                "ProviderName"
            ),

            "channel": get(
                data,
                "Channel",
                "channel"
            ),

            "image": get(
                data,
                "Image",
                "image",
                "ProcessName"
            ),

            "command_line": get(
                data,
                "CommandLine",
                "command_line",
                "commandline"
            ),

            "parent_image": get(
                data,
                "ParentImage",
                "parent_image",
                "ParentProcessName"
            ),

            "parent_command_line": get(
                data,
                "ParentCommandLine",
                "parent_command_line"
            ),

            "user": get(
                data,
                "User",
                "user",
                "SubjectUserName"
            ),

            "timestamp": get(
                data,
                "UtcTime",
                "Timestamp",
                "TimeCreated"
            ),

            "raw_json": json.dumps(data)
        }

        events.append(event)


print()
print("Events parsed:", len(events))

# ============================================================
# INSERT + DETECT
# ============================================================

for e in events:

    cur.execute("""
        INSERT INTO events (
            event_id,
            provider,
            channel,
            image,
            command_line,
            parent_image,
            parent_command_line,
            user,
            timestamp,
            raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        e["event_id"],
        e["provider"],
        e["channel"],
        e["image"],
        e["command_line"],
        e["parent_image"],
        e["parent_command_line"],
        e["user"],
        e["timestamp"],
        e["raw_json"]
    ))

    db_event_id = cur.lastrowid

    image = basename(e["image"])
    parent = basename(e["parent_image"])

    # MSHTA
    if image == "mshta.exe":

        create_alert(
            "Suspicious MSHTA Execution",
            "MEDIUM",
            "T1218.005",
            "Mshta",
            "MSHTA process execution detected.",
            db_event_id
        )

    # RUNDLL32
    if image == "rundll32.exe":

        create_alert(
            "Suspicious Rundll32 Execution",
            "MEDIUM",
            "T1218.011",
            "Rundll32",
            "Rundll32 execution detected.",
            db_event_id
        )

    # CORRELATION
    if image == "rundll32.exe" and parent == "mshta.exe":

        create_alert(
            "MSHTA → RUNDLL32 Process Chain",
            "HIGH",
            "T1218",
            "System Binary Proxy Execution",
            "Rundll32 was spawned by MSHTA.",
            db_event_id
        )

    # CMD
    if image == "cmd.exe":

        create_alert(
            "Command Shell Activity",
            "LOW",
            "T1059.003",
            "Windows Command Shell",
            "Windows command shell execution detected.",
            db_event_id
        )

    # POWERSHELL
    if image in ("powershell.exe", "pwsh.exe"):

        create_alert(
            "PowerShell Execution",
            "MEDIUM",
            "T1059.001",
            "PowerShell",
            "PowerShell execution detected.",
            db_event_id
        )

    # SCRIPT HOST
    if image in ("wscript.exe", "cscript.exe"):

        create_alert(
            "Windows Script Host Execution",
            "MEDIUM",
            "T1059.005",
            "Visual Basic",
            "Windows Script Host activity detected.",
            db_event_id
        )

    # REGSVR32
    if image == "regsvr32.exe":

        create_alert(
            "Regsvr32 Execution",
            "MEDIUM",
            "T1218.010",
            "Regsvr32",
            "Regsvr32 execution detected.",
            db_event_id
        )

    # CERTUTIL
    if image == "certutil.exe":

        create_alert(
            "Certutil Activity",
            "MEDIUM",
            "T1140",
            "Deobfuscate/Decode Files",
            "Certutil activity detected.",
            db_event_id
        )

    # WMIC
    if image == "wmic.exe":

        create_alert(
            "WMIC Activity",
            "MEDIUM",
            "T1047",
            "Windows Management Instrumentation",
            "WMIC execution detected.",
            db_event_id
        )

    # SCHTASKS
    if image == "schtasks.exe":

        create_alert(
            "Scheduled Task Activity",
            "MEDIUM",
            "T1053.005",
            "Scheduled Task",
            "Scheduled task execution detected.",
            db_event_id
        )


conn.commit()

# ============================================================
# VERIFY
# ============================================================

event_count = cur.execute(
    "SELECT COUNT(*) FROM events"
).fetchone()[0]

alert_count = cur.execute(
    "SELECT COUNT(*) FROM alerts"
).fetchone()[0]

high = cur.execute(
    "SELECT COUNT(*) FROM alerts WHERE severity='HIGH'"
).fetchone()[0]

medium = cur.execute(
    "SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'"
).fetchone()[0]

low = cur.execute(
    "SELECT COUNT(*) FROM alerts WHERE severity='LOW'"
).fetchone()[0]

print()
print("================================================")
print(" CLEAN DATABASE READY")
print("================================================")
print("Events  :", event_count)
print("Alerts  :", alert_count)
print("HIGH    :", high)
print("MEDIUM  :", medium)
print("LOW     :", low)
print("================================================")

print()
print("ALERT LIST:")

for row in cur.execute("""
    SELECT id, title, severity, technique
    FROM alerts
    ORDER BY id
"""):

    print(
        f"#{row[0]} | {row[1]} | {row[2]} | {row[3]}"
    )

conn.close()
