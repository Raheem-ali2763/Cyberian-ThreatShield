# Cyberian ThreatShield - Data Dictionary

## Dataset Information

| Item | Value |
|---|---|
| Dataset | EVTX-ATTACK-SAMPLES |
| Sample | maldoc_mshta_via_shellbrowserwind_rundll32.evtx |
| Normalized format | JSONL |
| Events analyzed | 11 |

## Event ID Summary

| Event ID | Count |
|---:|---:|
| 1 | 5 |
| 4663 | 6 |

## Provider Summary

| Provider | Count |
|---|---:|
| `Microsoft-Windows-Security-Auditing` | 6 |
| `Microsoft-Windows-Sysmon` | 5 |

## Channel Summary

| Channel | Count |
|---|---:|
| `Security` | 6 |
| `Microsoft-Windows-Sysmon/Operational` | 5 |

## Event Data Fields

| Field | Event IDs | Occurrences | Example |
|---|---|---:|---|
| `AccessList` | 4663 | 6 | `%%4432` |
| `AccessMask` | 4663 | 6 | `0x00000001` |
| `CommandLine` | 1 | 5 | `"C:\Program Files\Microsoft Office\Office14\WINWORD.EXE" /n "C:\Users\IEUser\Desktop\stats.doc"` |
| `Company` | 1 | 5 | `Microsoft Corporation` |
| `CurrentDirectory` | 1 | 5 | `C:\Users\IEUser\Desktop\` |
| `Description` | 1 | 5 | `Microsoft Word` |
| `FileVersion` | 1 | 5 | `14.0.4762.1000` |
| `HandleId` | 4663 | 6 | `0x00000000000007a4` |
| `Hashes` | 1 | 5 | `SHA1=FEA4E441ECCC4F8A1FB1E4480C5BC34F2D200BB6,MD5=9C82A9B1BD5C42B62B9AA2657B042819,SHA256=C0A081E6D5E0279BE4503F26F0B01BCEDEEBF1DFB95FCBE4FB935F881...` |
| `Image` | 1 | 5 | `C:\Program Files\Microsoft Office\Office14\WINWORD.EXE` |
| `IntegrityLevel` | 1 | 5 | `Medium` |
| `LogonGuid` | 1 | 5 | `{747f3d96-1231-610f-0000-002057a80700}` |
| `LogonId` | 1 | 5 | `0x000000000007a857` |
| `ObjectName` | 4663 | 6 | `\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\{c08afd90-f2a1-11d1-8455-00a0c91f3880}` |
| `ObjectServer` | 4663 | 6 | `Security` |
| `ObjectType` | 4663 | 6 | `Key` |
| `OriginalFileName` | 1 | 5 | `WinWord.exe` |
| `ParentCommandLine` | 1 | 5 | `C:\Windows\Explorer.EXE` |
| `ParentImage` | 1 | 5 | `C:\Windows\explorer.exe` |
| `ParentProcessGuid` | 1 | 5 | `{747f3d96-1239-610f-0000-0010d0210a00}` |
| `ParentProcessId` | 1 | 5 | `600` |
| `ProcessGuid` | 1 | 5 | `{747f3d96-1829-610f-0000-0010a33fd200}` |
| `ProcessId` | 1, 4663 | 11 | `3424` |
| `ProcessName` | 4663 | 6 | `C:\Program Files\Microsoft Office\Office14\WINWORD.EXE` |
| `Product` | 1 | 5 | `Microsoft Office 2010` |
| `ResourceAttributes` | 4663 | 6 | `-` |
| `RuleName` | 1 | 5 | `` |
| `SubjectDomainName` | 4663 | 6 | `MSEDGEWIN10` |
| `SubjectLogonId` | 4663 | 6 | `0x000000000007a857` |
| `SubjectUserName` | 4663 | 6 | `IEUser` |
| `SubjectUserSid` | 4663 | 6 | `S-1-5-21-3461203602-4096304019-2269080069-1000` |
| `TerminalSessionId` | 1 | 5 | `1` |
| `User` | 1 | 5 | `MSEDGEWIN10\IEUser` |
| `UtcTime` | 1 | 5 | `2021-08-07 23:32:57.315` |
