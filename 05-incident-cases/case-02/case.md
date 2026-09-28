# Incident Case 02 - Command Shell Activity

## Case Type

Windows command interpreter activity.

## Evidence

Sysmon Event ID 1.

Observed executable:

cmd.exe

Observed command line includes:

cmd /c start /min

and a batch file execution.

## Investigation

Review:

- Process tree
- User
- CommandLine
- ParentProcessId
- ParentImage
- Hashes
- Related Security events

## ATT&CK Mapping

T1059.003 - Windows Command Shell

## Limitation

The available sample does not provide enough surrounding telemetry to
determine full incident scope.

## Closure

Retain evidence and correlate with additional endpoint and authentication
telemetry.
