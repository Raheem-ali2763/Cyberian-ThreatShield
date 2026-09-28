# Incident Case 01 - MSHTA to Rundll32 Chain

## Case Type

Malicious-document / script interpreter activity.

## Evidence

Source:
EVTX-ATTACK-SAMPLES

Observed process sequence:

WINWORD.EXE
↓
MSHTA.EXE
↓
RUNDLL32.EXE

## Timeline

2021-08-07 23:32:57 - WINWORD.EXE observed.

2021-08-07 23:33:01 - MSHTA.EXE observed executing an HTA file.

2021-08-07 23:33:08 - RUNDLL32.EXE observed with MSHTA as parent.

## ATT&CK Mapping

T1218.005 - Mshta

T1218.011 - Rundll32

## Impact Assessment

The available sample demonstrates suspicious execution telemetry.
Impact to a real production environment cannot be determined from this
sample alone.

## Closure

Preserve the EVTX evidence, document the process chain, validate hashes,
and investigate surrounding telemetry when available.
