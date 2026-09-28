import sqlite3
import json
from pathlib import Path
from datetime import datetime

DB = Path("application/data/threatshield.db")

conn = sqlite3.connect(DB)
cur = conn.cursor()

# ============================================================
# RECURSIVE FIELD FINDER
# ============================================================

def find_value(obj, wanted_keys):

    wanted = {
        str(x).lower()
        for x in wanted_keys
    }

    if isinstance(obj, dict):

        for key, value in obj.items():

            if str(key).lower() in wanted:

                if value not in (None, ""):

                    if isinstance(value, (str, int, float)):
                        return str(value)

            result = find_value(value, wanted_keys)

            if result not in (None, ""):
                return result

    elif isinstance(obj, list):

        for item in obj:

            result = find_value(item, wanted_keys)

            if result not in (None, ""):
                return result

    return ""


def basename(value):

    if not value:
        return ""

    return (
        value
        .replace("\\", "/")
        .split("/")[-1]
        .lower()
    )


# ============================================================
# LOAD EVENTS
# ============================================================

rows = cur.execute("""
    SELECT id, raw_json
    FROM events
    ORDER BY id
""").fetchall()

print()
print("Events found:", len(rows))

if not rows:
    print("ERROR: No events in database.")
    conn.close()
    raise SystemExit(1)


# ============================================================
# CLEAR OLD ALERTS
# ============================================================

cur.execute("DELETE FROM alerts")
conn.commit()

print("[+] Old alerts cleared.")


# ============================================================
# REPAIR EVENTS
# ============================================================

repaired = 0
detections = 0

for event_db_id, raw in rows:

    try:
        data = json.loads(raw)
    except Exception as e:
        print(
            f"[!] Event #{event_db_id}: invalid raw JSON"
        )
        continue


    event_id = find_value(
        data,
        [
            "EventID",
            "EventId",
            "event_id",
            "EventIDValue"
        ]
    )

    provider = find_value(
        data,
        [
            "Provider",
            "ProviderName",
            "provider"
        ]
    )

    channel = find_value(
        data,
        [
            "Channel",
            "channel"
        ]
    )

    image = find_value(
        data,
        [
            "Image",
            "ProcessName",
            "process_name",
            "image"
        ]
    )

    command_line = find_value(
        data,
        [
            "CommandLine",
            "commandline",
            "command_line"
        ]
    )

    parent_image = find_value(
        data,
        [
            "ParentImage",
            "ParentProcessName",
            "parent_image",
            "parent_process_name"
        ]
    )

    parent_command_line = find_value(
        data,
        [
            "ParentCommandLine",
            "parent_command_line"
        ]
    )

    user = find_value(
        data,
        [
            "User",
            "UserName",
            "SubjectUserName",
            "user"
        ]
    )

    timestamp = find_value(
        data,
        [
            "UtcTime",
            "TimeCreated",
            "Timestamp",
            "timestamp"
        ]
    )


    # --------------------------------------------------------
    # UPDATE EVENT
    # --------------------------------------------------------

    cur.execute("""
        UPDATE events
        SET
            event_id=?,
            provider=?,
            channel=?,
            image=?,
            command_line=?,
            parent_image=?,
            parent_command_line=?,
            user=?,
            timestamp=?
        WHERE id=?
    """, (
        event_id,
        provider,
        channel,
        image,
        command_line,
        parent_image,
        parent_command_line,
        user,
        timestamp,
        event_db_id
    ))

    repaired += 1


    # --------------------------------------------------------
    # PRINT WHAT WAS FOUND
    # --------------------------------------------------------

    print()
    print(
        f"EVENT #{event_db_id}"
    )
    print(
        "  EventID :", event_id or "—"
    )
    print(
        "  Image   :", image or "—"
    )
    print(
        "  Parent  :", parent_image or "—"
    )
    print(
        "  User    :", user or "—"
    )


# Commit repaired telemetry
conn.commit()


# ============================================================
# DETECTION ENGINE
# ============================================================

print()
print("================================================")
print(" RUNNING DETECTION ENGINE")
print("================================================")


def create_alert(
    title,
    severity,
    technique,
    technique_name,
    description,
    event_id
):

    global detections

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

    detections += 1


events = cur.execute("""
    SELECT
        id,
        image,
        command_line,
        parent_image
    FROM events
    ORDER BY id
""").fetchall()


for event_db_id, image, command_line, parent_image in events:

    image_name = basename(image)
    parent_name = basename(parent_image)


    # ========================================================
    # MSHTA
    # ========================================================

    if image_name == "mshta.exe":

        create_alert(
            "Suspicious MSHTA Execution",
            "MEDIUM",
            "T1218.005",
            "Mshta",
            "MSHTA process execution detected in telemetry.",
            event_db_id
        )


    # ========================================================
    # RUNDLL32
    # ========================================================

    if image_name == "rundll32.exe":

        create_alert(
            "Suspicious Rundll32 Execution",
            "MEDIUM",
            "T1218.011",
            "Rundll32",
            "Rundll32 execution detected in telemetry.",
            event_db_id
        )


    # ========================================================
    # MSHTA -> RUNDLL32
    # ========================================================

    if (
        image_name == "rundll32.exe"
        and parent_name == "mshta.exe"
    ):

        create_alert(
            "MSHTA → RUNDLL32 Process Chain",
            "HIGH",
            "T1218",
            "System Binary Proxy Execution",
            "Rundll32 was spawned by MSHTA.",
            event_db_id
        )


    # ========================================================
    # CMD
    # ========================================================

    if image_name == "cmd.exe":

        create_alert(
            "Command Shell Activity",
            "LOW",
            "T1059.003",
            "Windows Command Shell",
            "Windows command shell execution detected.",
            event_db_id
        )


    # ========================================================
    # POWERSHELL
    # ========================================================

    if image_name in [
        "powershell.exe",
        "pwsh.exe"
    ]:

        create_alert(
            "PowerShell Execution",
            "MEDIUM",
            "T1059.001",
            "PowerShell",
            "PowerShell execution detected.",
            event_db_id
        )


    # ========================================================
    # SCRIPT HOST
    # ========================================================

    if image_name in [
        "wscript.exe",
        "cscript.exe"
    ]:

        create_alert(
            "Windows Script Host Execution",
            "MEDIUM",
            "T1059.005",
            "Visual Basic",
            "Windows Script Host execution detected.",
            event_db_id
        )


    # ========================================================
    # REGSVR32
    # ========================================================

    if image_name == "regsvr32.exe":

        create_alert(
            "Regsvr32 Execution",
            "MEDIUM",
            "T1218.010",
            "Regsvr32",
            "Regsvr32 execution detected.",
            event_db_id
        )


    # ========================================================
    # WMIC
    # ========================================================

    if image_name == "wmic.exe":

        create_alert(
            "WMIC Activity",
            "MEDIUM",
            "T1047",
            "Windows Management Instrumentation",
            "WMIC execution detected.",
            event_db_id
        )


    # ========================================================
    # SCHTASKS
    # ========================================================

    if image_name == "schtasks.exe":

        create_alert(
            "Scheduled Task Activity",
            "MEDIUM",
            "T1053.005",
            "Scheduled Task",
            "Scheduled task activity detected.",
            event_db_id
        )


conn.commit()


# ============================================================
# FINAL STATUS
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
print(" TELEMETRY REPAIR COMPLETE")
print("================================================")
print("Events repaired :", repaired)
print("Events total    :", event_count)
print("Alerts created  :", alert_count)
print("HIGH            :", high)
print("MEDIUM          :", medium)
print("LOW             :", low)
print("================================================")


# ============================================================
# SHOW PROCESSES
# ============================================================

print()
print("PROCESSES NOW STORED:")

for row in cur.execute("""
    SELECT id, image, parent_image, command_line
    FROM events
    ORDER BY id
"""):

    print(
        f"#{row[0]} | "
        f"{row[1] or '—'} | "
        f"Parent: {row[2] or '—'}"
    )


# ============================================================
# SHOW ALERTS
# ============================================================

print()
print("DETECTIONS:")

for row in cur.execute("""
    SELECT id,title,severity,technique
    FROM alerts
    ORDER BY id
"""):

    print(
        f"#{row[0]} | "
        f"{row[1]} | "
        f"{row[2]} | "
        f"{row[3]}"
    )


conn.close()

