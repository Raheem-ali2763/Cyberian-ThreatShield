# IOC Research and Correlation

## Observed Hash Evidence

The normalized Sysmon telemetry contains SHA1, MD5, SHA256 and IMPHASH
values for observed processes.

## Important Observed Processes

- WINWORD.EXE
- mshta.exe
- rundll32.exe
- svchost.exe
- cmd.exe

## IOC Handling

Observed hashes should be validated against trusted malware intelligence
sources before being classified as malicious.

## Correlation Fields

- SHA256
- SHA1
- MD5
- IMPHASH
- ProcessGuid
- ProcessId
- User
- Image
- CommandLine
- ParentImage
