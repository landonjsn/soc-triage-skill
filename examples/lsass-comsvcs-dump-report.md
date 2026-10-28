# Triage Report: LSASS memory dump via comsvcs.dll on WORKSTATION5

**Decision:** Escalate
**Severity:** Critical (active credential theft)
**Confidence:** High
**Summary:** On WORKSTATION5, user `wardog` used PowerShell to run `rundll32.exe comsvcs.dll MiniDump` against lsass.exe. The result was a full memory dump at `C:\Users\wardog\AppData\Local\Temp\lsass-comsvcs.dmp`, which contains credential material from every logged-on session.

## Scope
- **Time range:** 2020-10-18 07:49:39.776 to 07:50:09.089 (about 30 seconds)
- **Hosts:** WORKSTATION5
- **Users:** `wardog` (27 events), `WORKSTATION5$` (2, routine search indexer exits)
- **Log sources present:** Security (40 events), Sysmon (144 events)
- **Missing:** PowerShell Operational (4103/4104), Defender Operational, logon events (4624/4672), Sysmon 3/22 network and DNS, and file-deletion events (Sysmon 23/26). Because these are absent, we can't see what PowerShell ran beyond this one command, how wardog logged on, or whether the dump left the host.
- **Events reviewed:** 184. Most common: Sysmon 10 (68), Sysmon 7 (30), Sysmon 12 (29), Sysmon 13 (15), 4658 (10). The rows in the export are out of order, so I sorted them by time.

## Timeline
| Time | User | Source / EventID | What happened |
|---|---|---|---|
| 07:49:39.776 | – | Security 1102 | Security log cleared, about 26 seconds before the activity |
| 07:50:04.640–.650 | (RID-500 hive) | Sysmon 12/13 | Explorer records an app switch to powershell.exe (FeatureUsage\AppSwitched, UserAssist). This indicates an interactive PowerShell window |
| 07:50:05.838–.846 | wardog | 4656/4663, Sysmon 12 | PowerShell reads environment and certificate-trust registry keys (normal startup) |
| 07:50:05.910 / .917 | wardog | **4688 + Sysmon 1** | powershell.exe spawns `rundll32.exe C:\windows\System32\comsvcs.dll MiniDump 756 C:\Users\wardog\AppData\Local\Temp\lsass-comsvcs.dmp full` |
| 07:50:05.935 | wardog | 4656/4663 | rundll32 reads `HKLM\SYSTEM\...\Control\Lsa` |
| 07:50:05.978 | wardog | 4656 | rundll32 requests a handle to lsass.exe, AccessMask 0x1410 |
| 07:50:05.998 | – | Sysmon 7 | rundll32 loads comsvcs.dll |
| 07:50:06.001 | – | **Sysmon 10 + 11** | rundll32 opens lsass.exe (0x1410). `lsass-comsvcs.dmp` is created |
| 07:50:06.009–.025 | wardog | **4656/4663, Sysmon 10** | rundll32 opens lsass.exe with **0x1fffff** (PROCESS_ALL_ACCESS). Two 4663 events show access 0x10 (VM_READ) on the lsass process object |
| 07:50:06.198–.208 | – | Sysmon 7 | rundll32 loads dbghelp.dll and dbgcore.dll, which provide the MiniDumpWriteDump engine |
| 07:50:06.220 | wardog | 4689 + Sysmon 5 | rundll32 exits, so the dump is complete |

## Key evidence
1. **The attacker command line** (4688 at .910, Sysmon 1 at .917). ParentProcessName is `powershell.exe` and SubjectUserName is `wardog`. Two sources independently record the same action.
2. **Direction is correct.** In both Sysmon 10 events, SourceImage is `rundll32.exe` and **TargetImage is `lsass.exe`**, with 0x1410 and then 0x1fffff. The Security 4656/4663 events on `\Device\HarddiskVolume2\Windows\System32\lsass.exe` (ObjectType `Process`, not File or Key) confirm it.
3. **File artifact.** Sysmon 11 shows `C:\Users\wardog\AppData\Local\Temp\lsass-comsvcs.dmp` written by rundll32.
4. **Dump engine loaded.** dbghelp.dll and dbgcore.dll load into rundll32 right after it accesses lsass.

## Noise ruled out
- **Explorer → powershell/conhost/Raccine/InputApp (0x1000, 0x1410, 0x2000):** Explorer queries the windows it manages. None of these involve lsass.
- **powershell → rundll32 (0x1fffff) and csrss → rundll32 (0x1fffff):** A parent opening the child it just created, and csrss handling a new process, are both normal parts of process creation.
- **svchost → svchost / MsMpEng / Explorer (0x1000, 0x40, 0x2000):** Routine service activity.
- **Sysmon 12 on `SystemCertificates\Disallowed` (21 events):** CryptoAPI checks the trust store when PowerShell loads. Keys are opened, no values are written.
- **4656/4663 on `Session Manager\Environment`:** PowerShell reads environment variables at startup.
- **UserAssist / ActivityDataModel / VirtualDesktop writes:** Explorer UI telemetry. Decoding the ROT13 gives `WindowsPowerShell\v1.0\powershell.exe` and `UEME_CTLSESSION`. These are useful context because they show interactive use, but they are not malicious.
- **Prefetch `RUNDLL32.EXE-B1101E56.pf`:** svchost writes this after any program runs.
- **Raccine.exe:** an open-source ransomware "vaccine" tool that was running on the host. Explorer only queried it.
- **5156/5158 (6 events):** Every field is empty in this export, so they can't be evaluated.

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1003.001 OS Credential Dumping: LSASS Memory | 4688/Sysmon 1 command line, Sysmon 10 into lsass (0x1410, 0x1fffff), Sysmon 11 `.dmp` |
| T1218.011 System Binary Proxy Execution: Rundll32 | rundll32 used to call the `MiniDump` export of a signed Windows DLL (comsvcs.dll) |
| T1059.001 Command and Scripting Interpreter: PowerShell | ParentProcessName `powershell.exe` on the 4688 event |
| *Possible:* T1070.001 Clear Windows Event Logs | 1102 at 07:49:39. See open questions, since this is likely lab setup |

## Recommended next steps (for Tier 2)
1. Isolate WORKSTATION5 and collect `lsass-comsvcs.dmp` with its hash. No deletion event exists, so the file is probably still there, but Sysmon 23/26 may not be configured.
2. Treat every credential cached on WORKSTATION5 at 07:50 as compromised. Identify the sessions that were logged on (4624 with logon types) and plan resets, starting with privileged accounts.
3. Determine whether wardog's activity was legitimate. Find the 4624 that started the session, its source, and its logon type. Note that the user hive Explorer wrote to is `S-1-5-21-…-500`, the **RID-500 built-in Administrator**, which suggests wardog may be a renamed built-in admin. Confirm this. If it's true, the account had the privileges needed to read lsass.
4. Pull PowerShell 4104 script block logs to find what else ran in that session, and look for exfiltration of the `.dmp` file (SMB/HTTP egress, archive tools, copies to shares).
5. Check Defender for detections. MsMpEng was active, but no alert appears in this export.
6. Hunt for reuse of these credentials elsewhere (4624 type 3/10, 4648) after 07:50:06.

## Detection
```spl
index=* (
  (EventID IN (1, 4688) CommandLine="*comsvcs*" (CommandLine="*minidump*" OR CommandLine="*#24*"))
  OR (EventID=10 TargetImage="*lsass.exe" NOT SourceImage IN ("*MsMpEng.exe","*csrss.exe","*wininit.exe"))
  OR (EventID=11 TargetFilename="*.dmp" Image="*rundll32.exe")
)
| stats min(TimeCreated) as first max(TimeCreated) as last values(EventID) as event_ids
        values(CommandLine) as cmdline values(GrantedAccess) as access values(TargetFilename) as files by Hostname
```
**Why this works:** It matches the technique itself (comsvcs plus MiniDump, or its ordinal `#24`), any non-allowlisted process opening lsass, and the dump file, so attackers can't avoid it by renaming the output or changing parents. I tested this logic against the export. It returns exactly the 5 attack events (4688, Sysmon 1, both Sysmon 10, Sysmon 11) and none of the 179 noise events. Field names follow this export (`EventID`, `Hostname`). With the Splunk Windows TA, use `EventCode` and `host` instead. In production, expect the lsass clause to need more allowlisting for EDR and backup agents.

## Open questions
- **PID 756 is never directly linked to lsass in this data**, because there is no lsass process creation event. Handle requests to lsass in the next 100 ms make it very likely.
- **The 1102 log clear:** it falls 26 seconds before the attack, and the user and host names (`wardog`, `WORKSTATION5`) match the OTRF Security-Datasets lab. That pattern looks like clearing the log for a clean capture, not a cover-up. In a real environment, an unexplained 1102 would still be escalated, and this export doesn't record who cleared it.
- **Exfiltration and credential reuse:** this export contains no network, DNS, or logon data, so it can't answer either question.

## Analyst notes

Two notes on checking my own work. My call that the 0x1fffff accesses from powershell and csrss are routine depends on those processes being the parent or subsystem of the new rundll32. That's the standard explanation, but it's an inference. The RID-500 point is also unconfirmed from this data alone.
