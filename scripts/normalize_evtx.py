import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from Evtx.Evtx import Evtx

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

def parse_evtx(evtx_path):
    results = []

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())

                system = root.find("e:System", NS)
                event_data = root.find("e:EventData", NS)

                if system is None:
                    continue

                provider = system.find("e:Provider", NS)
                event_id = system.find("e:EventID", NS)
                level = system.find("e:Level", NS)
                time_created = system.find("e:TimeCreated", NS)
                computer = system.find("e:Computer", NS)
                channel = system.find("e:Channel", NS)

                event = {
                    "source_file": str(evtx_path),
                    "event_record_id": (
                        system.findtext("e:EventRecordID", default="", namespaces=NS)
                    ),
                    "provider": (
                        provider.attrib.get("Name", "")
                        if provider is not None
                        else ""
                    ),
                    "event_id": (
                        event_id.text
                        if event_id is not None
                        else ""
                    ),
                    "level": (
                        level.text
                        if level is not None
                        else ""
                    ),
                    "timestamp": (
                        time_created.attrib.get("SystemTime", "")
                        if time_created is not None
                        else ""
                    ),
                    "computer": (
                        computer.text
                        if computer is not None
                        else ""
                    ),
                    "channel": (
                        channel.text
                        if channel is not None
                        else ""
                    ),
                    "event_data": {}
                }

                if event_data is not None:
                    for data in event_data.findall("e:Data", NS):
                        name = data.attrib.get("Name", "")
                        value = data.text or ""

                        if name:
                            event["event_data"][name] = value.strip()

                results.append(event)

            except Exception as exc:
                print(
                    f"WARNING: Failed to parse record in "
                    f"{evtx_path}: {exc}",
                    file=sys.stderr
                )

    return results


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: python scripts/normalize_evtx.py "
            "<input.evtx> <output.jsonl>"
        )
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"ERROR: Input file not found: {input_file}")
        sys.exit(1)

    events = parse_evtx(input_file)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    print("=" * 70)
    print("NORMALIZATION COMPLETE")
    print("=" * 70)
    print(f"Input : {input_file}")
    print(f"Output: {output_file}")
    print(f"Events: {len(events)}")


if __name__ == "__main__":
    main()
