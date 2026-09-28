# Threat Hunt 01 - Suspicious Script Interpreter Chains

## Hypothesis

An attacker may abuse Windows script interpreters such as MSHTA and Rundll32
to execute content while blending activity with trusted Windows binaries.

## Data Source

EVTX-ATTACK-SAMPLES normalized Sysmon process creation telemetry.

## Hunting Method

Review Event ID 1 and inspect:

- Image
- CommandLine
- ParentImage
- ParentCommandLine
- User
- IntegrityLevel

## Observed Evidence

The analyzed sample contains:

WINWORD.EXE → MSHTA.EXE → RUNDLL32.EXE

The Rundll32 event has MSHTA as its parent process.

## Conclusion

The sample demonstrates telemetry useful for hunting process-proxy
execution chains. Further datasets are required before generalizing this
observation to a production baseline.

## ATT&CK

T1218.005 - Mshta

T1218.011 - Rundll32
