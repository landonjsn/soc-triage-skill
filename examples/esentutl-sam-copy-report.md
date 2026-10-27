# Triage Report: SAM Registry Hive Copied with esentutl on WORKSTATION5

**Decision:** Escalate
**Severity:** High
**Confidence:** High
**Summary:** User `wardog` used the built-in esentutl.exe utility on WORKSTATION5 to copy the SAM registry hive, which stores local account password hashes, out of a Volume Shadow Copy to `C:\ProgramData\SAM`.

## Scope
- **Time range:** 2020-10-19 12:28:23 to 12:29:00 (about 36 seconds)
- **Hosts:** WORKSTATION5
- **Users:** wardog (interactive user), WORKSTATION5$ (machine account, VSS activity)
- **Log sources:** Windows Security, Windows System, Sysmon | **Missing:** network and EDR data, so exfiltration cannot be ruled in or out
- **Events reviewed:** 915 (top: Sysmon 10 = 245, Sysmon 13 = 208, Security 4799 = 186, Sysmon 9 = 117)
- **Dataset:** OTRF Security Datasets, `cmd_sam_copy_esentutl`

## Timeline
| Time | Host | User | Source / EventID | What happened |
|---|---|---|---|---|
| 12:28:23.942 | WORKSTATION5 | n/a | Security 1102, System 104 | Security and System logs cleared (see Noise ruled out) |
| 12:28:31.089 | WORKSTATION5 | wardog | Security 4688, Sysmon 1 | cmd.exe launched `esentutl.exe /y /vss C:\windows/system32/config/SAM /d C:\ProgramData\SAM` |
| 12:28:31.327 | WORKSTATION5 | wardog | Security 4656, 4663 | esentutl.exe read the `HKLM\SYSTEM\ControlSet001\Control\Lsa` registry key |
| 12:28:31.362 | WORKSTATION5 | wardog | Sysmon 18 | esentutl.exe connected to the `\lsass` named pipe |
| 12:28:31 to 12:28:36 | WORKSTATION5 | WORKSTATION5$ | Sysmon 9, 11; Security 4904, 4905 | Volume Shadow Copy created (VSSVC.exe raw disk reads, new file under System Volume Information) |
| 12:28:36.083 | WORKSTATION5 | wardog | Sysmon 11 | esentutl.exe created `C:\ProgramData\SAM` |
| 12:28:36.162 | WORKSTATION5 | wardog | Security 4689, Sysmon 5 | esentutl.exe exited |

## Key evidence
1. **Process creation (4688 and Sysmon 1):** `esentutl.exe /y /vss C:\windows/system32/config/SAM /d C:\ProgramData\SAM`, parent `cmd.exe`, user `wardog`. The `/vss` option copies from a shadow copy, which gets around the lock Windows keeps on the live SAM file. Note the mixed slashes in the path, which can defeat detections that match on exact paths.
2. **File artifact (Sysmon 11):** `C:\ProgramData\SAM` was created by esentutl.exe five seconds later. The copy succeeded.
3. **Supporting context:** esentutl.exe loaded `samlib.dll` and `vss_ps.dll` (Sysmon 7) and read the LSA registry key (4663). Both are consistent with shadow copy and SAM handling.

## Noise ruled out
- **lsass.exe opening esentutl.exe and vssvc.exe (Sysmon 10, 188 events):** lsass.exe is the source, not the target, and GrantedAccess is `0x1000` (query limited information). This is routine. Credential dumping from memory would show a process opening **lsass.exe** with read rights such as `0x1010`. No such events exist here.
- **4799 group enumeration (186 events):** Administrators and Backup Operators checks by esentutl.exe and VSSVC.exe. This is a side effect of Volume Shadow Copy privilege checks, not separate discovery activity.
- **Sysmon 9 raw disk reads, 4904 and 4905, System Volume Information file:** expected side effects of creating a shadow copy.
- **4663 on the Lsa registry key:** a registry read, not a read of the SAM file. It supports the timeline but is not the proof of theft. The proof is the command line and the created file.
- **Log clearing (1102 and 104):** happened 7 seconds **before** the attack and with no attacker process tied to it. In OTRF datasets, logs are typically cleared right before the simulation to produce a clean capture. In a production environment, this would still be escalated and investigated as possible defense evasion (T1070.001).

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1003.002 OS Credential Dumping: Security Account Manager | 4688 and Sysmon 1 command line copying `config\SAM`; Sysmon 11 creation of `C:\ProgramData\SAM` |
| T1059.003 Command and Scripting Interpreter: Windows Command Shell | Parent process `cmd.exe` |
| T1070.001 Clear Windows Event Logs (possible) | 1102 and 104. Likely lab setup based on timing. Confirm by checking who cleared the logs. |

## Recommended next steps (for Tier 2)
1. Isolate WORKSTATION5 from the network pending investigation.
2. Collect `C:\ProgramData\SAM` as evidence, then remove it from the host.
3. Look for a copy of the SYSTEM hive as well. SAM hashes cannot be decrypted without the SYSTEM boot key, so an attacker would normally take both. Its absence here may mean the dataset only captured part of the activity.
4. Review how `wardog` logged on (4624 logon type and source IP) and whether the account is expected to have admin rights.
5. Check for file transfer or network connections from WORKSTATION5 after 12:28:36 to determine whether the file left the host.
6. Reset local account passwords on WORKSTATION5, and on any host that shares the same local administrator password.

## Detection
```spl
index=otrf
    ( (EventID=4688 OR EventID=1)
      (CommandLine="*esentutl*" OR CommandLine="*reg*save*")
      (CommandLine="*config*SAM*" OR CommandLine="*config*SYSTEM*" OR CommandLine="*config*SECURITY*"
       OR CommandLine="*HKLM*SAM*" OR CommandLine="*HKLM*SYSTEM*" OR CommandLine="*HKLM*SECURITY*") )
    OR
    ( EventID=11
      (TargetFilename="*\\SAM" OR TargetFilename="*\\SYSTEM" OR TargetFilename="*\\SECURITY")
      NOT TargetFilename="*System32*config*" )
| eval Process=coalesce(Image, NewProcessName)
| table _time Hostname EventID Process CommandLine TargetFilename
| sort _time
```
**Why this works:** It matches the behavior from two independent sources, the command line and the file it produces, so it still fires if one log source is missing. Wildcards around `config` and the hive name catch mixed slash directions. Tested against this dataset, it returns exactly the 3 attack events (4688, Sysmon 1, Sysmon 11) and no false positives.

## Open questions
- Was the SYSTEM hive also copied? Without it, the SAM copy alone cannot be decrypted.
- Did the copied file leave the host?
- Who cleared the logs at 12:28:23, and why?
