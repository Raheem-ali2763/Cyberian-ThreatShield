import json
from pathlib import Path
from collections import Counter

src = Path("datasets/processed/maldoc_mshta_sample.jsonl")
out = Path("reports/telemetry_evidence.md")

events = [json.loads(x) for x in src.read_text().splitlines() if x.strip()]

event_ids = Counter(str(x.get("event_id")) for x in events)
images = Counter(
    x.get("event_data", {}).get("Image", "")
    for x in events
    if x.get("event_data", {}).get("Image")
)

with out.open("w") as f:
    f.write("# Cyberian ThreatShield - Telemetry Evidence Report\n\n")
    f.write("## Dataset\n\n")
    f.write("EVTX-ATTACK-SAMPLES normalized telemetry.\n\n")
    f.write(f"Total normalized events: **{len(events)}**\n\n")

    f.write("## Event IDs Observed\n\n")
    for k, v in event_ids.items():
        f.write(f"- Event ID `{k}`: {v} events\n")

    f.write("\n## Process Images Observed\n\n")
    for image, count in images.items():
        f.write(f"- `{image}` — {count}\n")

    f.write("\n## Observed Process Relationships\n\n")

    for e in events:
        d = e.get("event_data", {})
        image = d.get("Image", "")
        parent = d.get("ParentImage", "")

        if image and parent and parent != "?":
            f.write(f"- `{parent}` → `{image}`\n")

    f.write("\n## Evidence Note\n\n")
    f.write(
        "This report contains observations extracted from the supplied "
        "normalized telemetry. It does not assert that every detection "
        "rule in the project is present in this sample.\n"
    )

print(f"Evidence report created: {out}")
