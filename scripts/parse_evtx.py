import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from Evtx.Evtx import Evtx

if len(sys.argv) != 2:
    print("Usage: python scripts/parse_evtx.py <file.evtx>")
    sys.exit(1)

evtx_file = Path(sys.argv[1])

if not evtx_file.exists():
    print(f"ERROR: File not found: {evtx_file}")
    sys.exit(1)

print("=" * 80)
print(f"FILE: {evtx_file}")
print("=" * 80)

count = 0
event_ids = {}
providers = {}
channels = {}
examples = []

with Evtx(str(evtx_file)) as log:
    for record in log.records():
        count += 1

        try:
            xml_text = record.xml()
            root = ET.fromstring(xml_text)

            system = root.find(
                "{http://schemas.microsoft.com/win/2004/08/events/event}System"
            )

            if system is None:
                continue

            event_id_element = system.find(
                "{http://schemas.microsoft.com/win/2004/08/events/event}EventID"
            )
            provider_element = system.find(
                "{http://schemas.microsoft.com/win/2004/08/events/event}Provider"
            )
            channel_element = system.find(
                "{http://schemas.microsoft.com/win/2004/08/events/event}Channel"
            )

            event_id = (
                event_id_element.text
                if event_id_element is not None
                else "UNKNOWN"
            )

            provider = (
                provider_element.attrib.get("Name", "UNKNOWN")
                if provider_element is not None
                else "UNKNOWN"
            )

            channel = (
                channel_element.text
                if channel_element is not None
                else "UNKNOWN"
            )

            event_ids[event_id] = event_ids.get(event_id, 0) + 1
            providers[provider] = providers.get(provider, 0) + 1
            channels[channel] = channels.get(channel, 0) + 1

            if len(examples) < 3:
                examples.append(xml_text)

        except Exception as e:
            print(f"WARNING: Could not parse record {count}: {e}")

print()
print("========== SUMMARY ==========")
print(f"Total records: {count}")

print()
print("========== EVENT IDs ==========")
for event_id, amount in sorted(
    event_ids.items(),
    key=lambda x: (-x[1], str(x[0]))
):
    print(f"EventID {event_id}: {amount}")

print()
print("========== PROVIDERS ==========")
for provider, amount in sorted(
    providers.items(),
    key=lambda x: (-x[1], x[0])
):
    print(f"{provider}: {amount}")

print()
print("========== CHANNELS ==========")
for channel, amount in sorted(
    channels.items(),
    key=lambda x: (-x[1], x[0])
):
    print(f"{channel}: {amount}")

print()
print("========== SAMPLE XML EVENTS ==========")
for index, xml_text in enumerate(examples, 1):
    print(f"\n----- SAMPLE EVENT {index} -----")
    print(xml_text[:5000])

print()
print("========== PARSING COMPLETE ==========")
