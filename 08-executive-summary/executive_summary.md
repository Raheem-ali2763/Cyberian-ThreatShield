# Executive Summary

Cyberian ThreatShield is a detection engineering and threat hunting
engagement focused on Windows security telemetry.

The project uses public EVTX security telemetry, Python-based normalization,
Sigma detection rules and MITRE ATT&CK mapping.

The analyzed sample demonstrated a process chain involving:

WINWORD.EXE → MSHTA.EXE → RUNDLL32.EXE

The project also includes detection content for command interpreters,
scheduled tasks, Windows utilities, discovery activity and system
administration tools.

The current evidence base is a public sample dataset. Production conclusions
require additional telemetry and environment-specific baselines.

## Key Deliverables

- Sigma detection rules
- Correlation rules
- ATT&CK coverage matrix
- Threat hunting reports
- Incident case reports
- IOC research
- Incident response playbooks
- Data dictionary
- Evidence documentation
