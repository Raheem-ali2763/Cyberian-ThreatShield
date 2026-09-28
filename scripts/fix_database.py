from pathlib import Path
import sqlite3
import json
from datetime import datetime

ROOT = Path.cwd()

# ------------------------------------------------
# FIND REAL JSONL AUTOMATICALLY
# ------------------------------------------------

files = list(ROOT.glob("datasets/processed/*.jsonl"))

if not files:
    files = list(ROOT.rglob("maldoc_mshta_sample.jsonl"))

print()
print("[1] Searching telemetry...")

for f in files:
    print("FOUND:", f)

if not files:
    print("ERROR: No JSONL telemetry file found.")
    raise SystemExit(1)

JSONL = files[0]

print()
print("Using:")
print(JSONL)

# ------------------------------------------------
# DATABASE
# ------------------------------------------------

DB = ROOT / "application" / "data" / "threatshield.db"

print()
print("[2] Database:")
print(DB)

if not DB.exists():
    print("ERROR: Database does not exist.")
    raise SystemExit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

# ------------------------------------------------
# ENSURE TABLES EXIST
# ------------------------------------------------

cur.execute("""
CREATE TABLE IF NOT EXISTS events (
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
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    severity TEXT,
    technique TEXT,
    technique_name TEXT,
    description TEXT,
    source_event_id INTEGER,
    status TEXT DEFAULT 'OPEN',
    created_at TEXT
)
""")

conn.commit()

# ------------------------------------------------
# HELPER
# ------------------------------------------------

def get(d, *names):
    for name in names:
        if name in d and d[name] not in (None, ""):
            return d[name]

    # case-insensitive lookup
    lower = {str(k).lower(): v for k, v in d.items()}

    for name in names:
        if name.lower() in lower and lower[name.lower()] not in (None, ""):
            return lower[name.lower()]

    return ""

# ------------------------------------------------
# READ JSONL
# ------------------------------------------------

print()
print("[3] Reading telemetry...")

events = []

with open(JSONL, "r", errors="ignore") as f:

    for line_number, line in enumerate(f, 1):

        line = line.strip()

        if not line:
            continue

        try:
            data = json.loads(line)
        except Exception as e:
            print("Skipping invalid JSON line:", line_number)
            continue

        event_id = get(
            data,
            "EventID",
            "event_id",
            "EventId",
            "eventid"
        )

        provider = get(
            data,
            "Provider",
            "provider",
            "ProviderName"
        )

        channel = get(
            data,
            "Channel",
            "channel"
        )

        image = get(
            data,
            "Image",
            "image",
            "ProcessName",
            "process_name"
        )

        command = get(
            data,
            "CommandLine",
            "command_line",
            "commandline"
        )

        parent = get(
            data,
            "ParentImage",
            "parent_image",
            "ParentProcessName",
            "parent_process_name"
        )

        parent_command = get(
            data,
            "ParentCommandLine",
            "parent_command_line"
        )

        user = get(
            data,
            "User",
            "user",
            "SubjectUserName"
        )

        timestamp = get(
            data,
            "UtcTime",
            "timestamp",
            "Timestamp",
            "TimeCreated"
        )

        events.append({
            "event_id": str(event_id),
            "provider": str(provider),
            "channel": str(channel),
            "image": str(image),
            "command_line": str(command),
            "parent_image": str(parent),
            "parent_command_line": str(parent_command),
            "user": str(user),
            "timestamp": str(timestamp),
            "raw": json.dumps(data)
        })

print("Events parsed:", len(events))

if not events:
    print("ERROR: JSONL contained no usable events.")
    conn.close()
    raise SystemExit(1)

# ------------------------------------------------
# INSERT EVENTS
# ------------------------------------------------

print()
print("[4] Inserting events...")

inserted = 0

for e in events:

    cur.execute("""
        INSERT INTO events
        (
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
        e["raw"]
    ))

    e["db_id"] = cur.lastrowid
    inserted += 1

conn.commit()

print("Events inserted:", inserted)

# ------------------------------------------------
# DETECTION ENGINE
# ------------------------------------------------

print()
print("[5] Running detection engine...")

def base(path):
    if not path:
        return ""

    return path.replace("\\", "/").split("/")[-1].lower()


alerts_created = 0


def alert(title, severity, technique, technique_name,
          description, event_id):

    global alerts_created

    cur.execute("""
        INSERT INTO alerts
        (
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

    alerts_created += 1


for e in events:

    image = base(e["image"])
    parent = base(e["parent_image"])
    command = e["command_line"].lower()

    # MSHTA
    if image == "mshta.exe":

        alert(
            "Suspicious MSHTA Execution",
            "MEDIUM",
            "T1218.005",
            "Mshta",
            "MSHTA process execution detected.",
            e["db_id"]
        )

    # RUNDLL32
    if image == "rundll32.exe":

        alert(
            "Suspicious Rundll32 Execution",
            "MEDIUM",
            "T1218.011",
            "Rundll32",
            "Rundll32 execution detected.",
            e["db_id"]
        )

    # MSHTA -> RUNDLL32
    if image == "rundll32.exe" and parent == "mshta.exe":

        alert(
            "MSHTA → RUNDLL32 Process Chain",
            "HIGH",
            "T1218",
            "System Binary Proxy Execution",
            "Rundll32 was spawned by MSHTA.",
            e["db_id"]
        )

    # CMD
    if image == "cmd.exe":

        alert(
            "Command Shell Activity",
            "LOW",
            "T1059.003",
            "Windows Command Shell",
            "Windows command shell execution detected.",
            e["db_id"]
        )

    # POWERSHELL
    if image in ("powershell.exe", "pwsh.exe"):

        alert(
            "PowerShell Execution",
            "MEDIUM",
            "T1059.001",
            "PowerShell",
            "PowerShell execution detected.",
            e["db_id"]
        )

    # WScript / CScript
    if image in ("wscript.exe", "cscript.exe"):

        alert(
            "Windows Script Host Execution",
            "MEDIUM",
            "T1059.005",
            "Visual Basic",
            "Windows Script Host activity detected.",
            e["db_id"]
        )

    # REGSVR32
    if image == "regsvr32.exe":

        alert(
            "Regsvr32 Execution",
            "MEDIUM",
            "T1218.010",
            "Regsvr32",
            "Regsvr32 execution detected.",
            e["db_id"]
        )

    # CERTUTIL
    if image == "certutil.exe":

        alert(
            "Certutil Activity",
            "MEDIUM",
            "T1140",
            "Deobfuscate/Decode Files",
            "Certutil activity detected.",
            e["db_id"]
        )

    # WMIC
    if image == "wmic.exe":

        alert(
            "WMIC Activity",
            "MEDIUM",
            "T1047",
            "Windows Management Instrumentation",
            "WMIC execution detected.",
            e["db_id"]
        )

    # SCHTASKS
    if image == "schtasks.exe":

        alert(
            "Scheduled Task Activity",
            "MEDIUM",
            "T1053.005",
            "Scheduled Task",
            "Scheduled task execution detected.",
            e["db_id"]
        )


conn.commit()

# ------------------------------------------------
# FINAL DATABASE STATUS
# ------------------------------------------------

events_count = cur.execute(
    "SELECT COUNT(*) FROM events"
).fetchone()[0]

alerts_count = cur.execute(
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
print(" DATABASE SUCCESSFULLY POPULATED")
print("================================================")
print("Events in DB :", events_count)
print("Alerts in DB :", alerts_count)
print("HIGH         :", high)
print("MEDIUM       :", medium)
print("LOW          :", low)
print("New alerts   :", alerts_created)
print("================================================")

print()
print("Latest alerts:")

rows = cur.execute("""
SELECT id,title,severity,technique
FROM alerts
ORDER BY id DESC
LIMIT 10
""").fetchall()

for r in rows:
    print(
        f"#{r[0]} | {r[1]} | {r[2]} | {r[3]}"
    )

conn.close()
