# Windows Event Reference for Triage

Quick reference for the events most useful in Tier 1 triage. "Signal" means how much the event tells you on its own.

## Windows Security log

| Event ID | Meaning | Signal | Triage notes |
|---|---|---|---|
| 1102 | Audit log cleared | High | Check timing and who cleared it. Unexplained clearing on a production host should be escalated. |
| 4624 | Successful logon | Low alone | Check Logon Type: 2 interactive, 3 network, 10 remote interactive (RDP). Unusual source IPs or times matter. |
| 4625 | Failed logon | Medium in bursts | Many failures for one account suggests brute force. One failure across many accounts suggests password spraying. |
| 4648 | Logon with explicit credentials | Medium | Common with runas. Can indicate lateral movement. |
| 4656 | Handle to an object requested | Low | Check ObjectName and ObjectType. Often paired with 4663. |
| 4663 | Attempt to access an object | Medium | Check ObjectType: "File" or "Key" (registry). Do not assume it is a file. |
| 4672 | Special privileges assigned to new logon | Low alone | Admin-equivalent logon. Matters when paired with other suspicious activity. |
| 4673 | Privileged service called | Low | Usually routine. Note the privilege named. |
| 4688 | New process created | High | The CommandLine field is the most valuable field in the Security log. Requires command line auditing to be enabled. |
| 4689 | Process exited | Low | Useful for timeline and process lifetime. |
| 4697 | Service installed | High | Common persistence and lateral movement technique. |
| 4698 | Scheduled task created | High | Common persistence technique. |
| 4720 | User account created | High | Unexpected local accounts are a persistence red flag. |
| 4728 / 4732 / 4756 | Member added to a security group (global / local / universal) | High | Especially Administrators or Domain Admins. |
| 4740 | Account locked out | Medium | Often follows a burst of 4625 events. |
| 4768 / 4769 | Kerberos TGT / service ticket requested | Low alone | Unusual encryption types (RC4, 0x17) on service tickets can indicate Kerberoasting. |
| 4776 | NTLM credential validation | Low alone | Bursts of failures indicate password attacks. |
| 4799 | Local group membership enumerated | Low | Often a side effect of normal tools, including Volume Shadow Copy checking Administrators and Backup Operators. |
| 4904 / 4905 | Security event source registered / unregistered | Low | VSSVC.exe registers here when a shadow copy is created. |
| 5156 / 5158 | Windows Filtering Platform allowed a connection / bind | Low | High volume. Use for network context only. |

## System log

| Event ID | Meaning | Signal | Triage notes |
|---|---|---|---|
| 104 | Event log cleared | High | System-log equivalent of 1102. |
| 7045 | Service installed | High | Same concern as 4697. |

## Sysmon (Microsoft-Windows-Sysmon/Operational)

| Event ID | Meaning | Signal | Triage notes |
|---|---|---|---|
| 1 | Process creation | High | Includes CommandLine, ParentImage, User, and hashes. Usually the best single event. |
| 3 | Network connection | Medium | Process plus destination IP and port. |
| 5 | Process terminated | Low | Timeline only. |
| 7 | Image (DLL) loaded | Low alone | Very noisy. Useful to confirm what a process did, such as loading vss_ps.dll or samlib.dll. |
| 8 | CreateRemoteThread | High | A classic process injection indicator. |
| 9 | RawAccessRead | Medium | Direct disk reads. Normal for VSSVC and some svchost activity. Suspicious from unusual processes. |
| 10 | Process access | Varies | Check direction. **Target = lsass.exe** with VM_READ rights is the credential dumping signal. Source = lsass.exe opening other processes with 0x1000 is routine. |
| 11 | File created | High | Shows artifacts such as copied hive files, dropped tools, or dump files. |
| 12 / 13 / 14 | Registry key created or deleted / value set / renamed | Medium | Focus on Run keys, services, and security settings. |
| 17 / 18 | Named pipe created / connected | Low alone | Context for inter-process communication. |
| 22 | DNS query | Medium | Process-level DNS. Useful for C2 and exfiltration domains. |
| 23 / 26 | File deleted | Medium | Can show cleanup of tools or dumps. |

## Sysmon 10 GrantedAccess values

| Value | Meaning | Triage notes |
|---|---|---|
| 0x1000 | PROCESS_QUERY_LIMITED_INFORMATION | Routine. |
| 0x1010 | Query limited information plus VM_READ | Against lsass.exe, a common credential dumping pattern. |
| 0x1410 | Query information plus query limited plus VM_READ | Against lsass.exe, suspicious. Against other processes, often routine. |
| 0x1438 / 0x143a | Read plus write and operation rights | Against lsass.exe, highly suspicious. |
| 0x1fffff | PROCESS_ALL_ACCESS | Against lsass.exe, highly suspicious unless from a known security product. |
| 0x100000 | SYNCHRONIZE | Routine. |
