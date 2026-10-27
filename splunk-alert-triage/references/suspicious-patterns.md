# Suspicious Patterns and ATT&CK Mapping

Command line and file patterns worth flagging during triage. A match is a lead, not a verdict. Always check the user, parent process, and context.

## Credential access

| Pattern | Example | ATT&CK |
|---|---|---|
| Copying registry hives with esentutl | `esentutl.exe /y /vss C:\Windows\System32\config\SAM /d C:\ProgramData\SAM` | T1003.002 Security Account Manager |
| Saving registry hives with reg.exe | `reg save HKLM\SAM sam.save`, `reg save HKLM\SYSTEM system.save` | T1003.002 Security Account Manager |
| Copying hives from a shadow copy | `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM` | T1003.002 Security Account Manager |
| Dumping LSASS with comsvcs.dll | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass PID> lsass.dmp full` | T1003.001 LSASS Memory |
| Dumping LSASS with procdump | `procdump -ma lsass.exe` | T1003.001 LSASS Memory |
| Process opening lsass.exe with read rights | Sysmon 10, TargetImage lsass.exe, GrantedAccess 0x1010 or 0x1410 | T1003.001 LSASS Memory |
| Extracting the domain database | `ntdsutil "ac i ntds" "ifm" "create full C:\temp"` | T1003.003 NTDS |
| A hive file appearing outside config | Sysmon 11, TargetFilename ending in `\SAM`, `\SYSTEM`, or `\SECURITY` outside `C:\Windows\System32\config\` | T1003.002 Security Account Manager |

Note: copying SAM alone is not enough to recover hashes. Attackers usually also take the SYSTEM hive, which holds the decryption key. If you see SAM copied, look for SYSTEM too.

## Execution

| Pattern | Example | ATT&CK |
|---|---|---|
| Command shell launching admin or credential tools | ParentImage `cmd.exe` | T1059.003 Windows Command Shell |
| Encoded PowerShell | `powershell -enc <base64>`, `-EncodedCommand` | T1059.001 PowerShell, T1027 Obfuscated Files or Information |
| PowerShell download cradle | `IEX (New-Object Net.WebClient).DownloadString(...)` | T1059.001 PowerShell, T1105 Ingress Tool Transfer |
| Signed binary proxy execution | `rundll32.exe`, `regsvr32.exe /i:http`, `mshta.exe http...` | T1218 System Binary Proxy Execution |

## Defense evasion

| Pattern | Example | ATT&CK |
|---|---|---|
| Clearing event logs | Security 1102, System 104, `wevtutil cl Security` | T1070.001 Clear Windows Event Logs |
| Deleting shadow copies | `vssadmin delete shadows /all /quiet` | T1490 Inhibit System Recovery |
| Downloading with certutil | `certutil -urlcache -split -f http://...` | T1105 Ingress Tool Transfer |

## Persistence and privilege

| Pattern | Example | ATT&CK |
|---|---|---|
| New local account | 4720, `net user <name> <password> /add` | T1136.001 Local Account |
| Added to Administrators | 4732, `net localgroup administrators <name> /add` | T1098 Account Manipulation |
| New service | 4697 or 7045 | T1543.003 Windows Service |
| New scheduled task | 4698, `schtasks /create` | T1053.005 Scheduled Task |
| Run key modification | Sysmon 13 on `...\CurrentVersion\Run` | T1547.001 Registry Run Keys |

## Credential attacks against logons

| Pattern | Example | ATT&CK |
|---|---|---|
| Many failed logons for one account | Burst of 4625 events, same TargetUserName | T1110.001 Password Guessing |
| One failed logon across many accounts | 4625 events, many TargetUserName values, same source | T1110.003 Password Spraying |
| Successful logon right after a failure burst | 4625 events followed by 4624 for the same account | T1110 Brute Force, then T1078 Valid Accounts |

## Expected side effects (do not report as separate attacks)

- Volume Shadow Copy activity (`/vss` options, vssadmin): VSSVC.exe process activity, 4904 and 4905, Sysmon 9 raw disk reads, files under `C:\System Volume Information\`, and 4799 checks of Administrators and Backup Operators.
- Prefetch files (`C:\Windows\Prefetch\*.pf`) created by svchost.exe after any program runs.
- lsass.exe opening newly created processes with GrantedAccess 0x1000.
