# ThreatShield IR Playbooks

## 1. Malware / Malicious Document Response

### Identify
- Review process creation telemetry
- Identify suspicious parent-child relationships
- Check command line arguments
- Identify related files and IOCs

### Contain
- Isolate affected endpoint
- Terminate confirmed malicious process
- Block identified malicious indicators

### Investigate
- Review process tree
- Review user and execution context
- Search related telemetry
- Map activity to MITRE ATT&CK

### Recover
- Remove malicious artifacts
- Restore affected systems if required
- Validate endpoint state
- Continue monitoring

---

## 2. Account Compromise Response

### Identify
- Review authentication events
- Identify unusual account activity
- Check source IP and login context

### Contain
- Disable or restrict compromised account
- Revoke active sessions
- Reset credentials

### Investigate
- Search related authentication telemetry
- Identify affected systems
- Determine persistence or lateral movement

### Recover
- Restore account access securely
- Enable additional monitoring
- Document findings

---

## 3. Suspicious PowerShell Response

### Identify
- Review PowerShell command line
- Identify encoded or suspicious commands
- Review parent process

### Contain
- Isolate affected endpoint when required
- Stop malicious process
- Block confirmed indicators

### Investigate
- Review process tree
- Search related events
- Map activity to ATT&CK

### Recover
- Remove persistence
- Validate endpoint
- Monitor for recurrence
