# Cyberian ThreatShield - Datasets

This directory contains public security telemetry used for detection engineering
and threat hunting.

## Dataset Categories

- EVTX Windows event logs
- Security datasets
- Zeek/network telemetry
- Raw downloaded evidence
- Processed/normalized telemetry

## Evidence Rules

1. Keep original downloaded files unchanged in `raw/`.
2. Store processed copies separately.
3. Record dataset source and acquisition date.
4. Do not fabricate log events.
5. Detection rules must be tested against actual telemetry.
