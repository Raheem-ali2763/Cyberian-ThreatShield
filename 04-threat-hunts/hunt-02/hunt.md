# Threat Hunt 02 - Suspicious Command Interpreter Activity

## Hypothesis

Attackers may use Windows command interpreters after initial execution to
perform follow-on actions.

## Data Source

Windows Sysmon Event ID 1 telemetry.

## Hunting Method

Search process creation events for:

- cmd.exe
- powershell.exe
- wscript.exe
- cscript.exe
- suspicious command-line arguments
- unusual parent-child relationships

## Observed Evidence

The current sample contains a cmd.exe process with a command line invoking
a batch file and registry modification.

## Limitation

The current dataset is a small sample. Additional telemetry is required
before establishing a normal enterprise baseline.

## ATT&CK

T1059.003 - Windows Command Shell
