# Cyberian ThreatShield - Telemetry Evidence Report

## Dataset

EVTX-ATTACK-SAMPLES normalized telemetry.

Total normalized events: **11**

## Event IDs Observed

- Event ID `1`: 5 events
- Event ID `4663`: 6 events

## Process Images Observed

- `C:\Program Files\Microsoft Office\Office14\WINWORD.EXE` — 1
- `C:\Windows\SysWOW64\mshta.exe` — 1
- `C:\Windows\System32\svchost.exe` — 1
- `C:\Windows\SysWOW64\rundll32.exe` — 1
- `C:\Windows\System32\cmd.exe` — 1

## Observed Process Relationships

- `C:\Windows\explorer.exe` → `C:\Program Files\Microsoft Office\Office14\WINWORD.EXE`
- `C:\Windows\explorer.exe` → `C:\Windows\SysWOW64\mshta.exe`
- `C:\Windows\SysWOW64\mshta.exe` → `C:\Windows\SysWOW64\rundll32.exe`

## Evidence Note

This report contains observations extracted from the supplied normalized telemetry. It does not assert that every detection rule in the project is present in this sample.
