import json
from collections import Counter, defaultdict
from pathlib import Path

INPUT = Path("datasets/processed/maldoc_mshta_sample.jsonl")
OUTPUT = Path("01-data-dictionary/data_dictionary.md")

if not INPUT.exists():
    print(f"ERROR: Input file not found: {INPUT}")
    raise SystemExit(1)

events = []

with INPUT.open("r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            events.append(json.loads(line))

event_id_counts = Counter(
    str(event.get("event_id", ""))
    for event in events
)

provider_counts = Counter(
    event.get("provider", "")
    for event in events
)

channel_counts = Counter(
    event.get("channel", "")
    for event in events
)

field_stats = defaultdict(
    lambda: {
        "count": 0,
        "event_ids": set(),
        "examples": []
    }
)

for event in events:
    event_id = str(event.get("event_id", ""))

    for field, value in event.get("event_data", {}).items():

        field_stats[field]["count"] += 1
        field_stats[field]["event_ids"].add(event_id)

        value = str(value)

        if (
            value not in field_stats[field]["examples"]
            and len(field_stats[field]["examples"]) < 3
        ):
            field_stats[field]["examples"].append(value)

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", encoding="utf-8") as f:

    f.write("# Cyberian ThreatShield - Data Dictionary\n\n")

    f.write("## Dataset Information\n\n")
    f.write("| Item | Value |\n")
    f.write("|---|---|\n")
    f.write("| Dataset | EVTX-ATTACK-SAMPLES |\n")
    f.write("| Sample | maldoc_mshta_via_shellbrowserwind_rundll32.evtx |\n")
    f.write("| Normalized format | JSONL |\n")
    f.write(f"| Events analyzed | {len(events)} |\n")

    f.write("\n## Event ID Summary\n\n")
    f.write("| Event ID | Count |\n")
    f.write("|---:|---:|\n")

    for event_id, count in sorted(event_id_counts.items()):
        f.write(f"| {event_id} | {count} |\n")

    f.write("\n## Provider Summary\n\n")
    f.write("| Provider | Count |\n")
    f.write("|---|---:|\n")

    for provider, count in provider_counts.most_common():
        f.write(f"| `{provider}` | {count} |\n")

    f.write("\n## Channel Summary\n\n")
    f.write("| Channel | Count |\n")
    f.write("|---|---:|\n")

    for channel, count in channel_counts.most_common():
        f.write(f"| `{channel}` | {count} |\n")

    f.write("\n## Event Data Fields\n\n")
    f.write(
        "| Field | Event IDs | Occurrences | Example |\n"
    )
    f.write(
        "|---|---|---:|---|\n"
    )

    def sort_key(field):
        return field.lower()

    for field in sorted(field_stats, key=sort_key):

        info = field_stats[field]

        event_ids = ", ".join(
            sorted(
                info["event_ids"],
                key=lambda x: int(x) if x.isdigit() else x
            )
        )

        example = (
            info["examples"][0]
            if info["examples"]
            else ""
        )

        example = (
            example
            .replace("|", "\\|")
            .replace("\n", " ")
            .replace("\r", " ")
        )

        if len(example) > 150:
            example = example[:147] + "..."

        f.write(
            f"| `{field}` | {event_ids} | "
            f"{info['count']} | `{example}` |\n"
        )

print("=" * 70)
print("DATA DICTIONARY GENERATED")
print("=" * 70)
print(f"Input file : {INPUT}")
print(f"Output file: {OUTPUT}")
print(f"Events     : {len(events)}")
print(f"Fields     : {len(field_stats)}")
