# SOC Alert Triage Skill for Claude

A Claude skill that turns raw Windows security events and Splunk search results into a Tier 1 SOC triage report: a timeline, the key evidence, the noise ruled out, a MITRE ATT&CK mapping, a severity rating, and a clear escalate, monitor, or close decision.

This builds on my [Home SIEM Lab](https://github.com/landonjsn/home-siem-lab), where I used Splunk to investigate a credential theft attack.

## Why I built it

Tier 1 triage is repetitive: pull the events, build a timeline, separate real signal from background noise, decide whether to escalate, and write it up. I wanted to see whether I could encode that process as a reusable AI workflow without letting the AI make things up. The skill forces every conclusion to point back to a specific event, and it requires the report to list what was ruled out as noise, not just what looks scary.

## What it does

Given a Splunk export, pasted events, or a raw log file, the skill walks through eight steps:

1. **Inventory** the data: time range, hosts, users, log sources, and which sources are missing
2. **Find anchor events**, such as process creation with command lines, file creation, and log clearing
3. **Build a timeline** in plain English
4. **Separate signal from noise**, including checking the direction of process access and recognizing side effects of normal Windows behavior
5. **Map to MITRE ATT&CK**, only where there is evidence
6. **Rate severity and confidence** using a defined rubric
7. **Decide**: escalate, monitor, or close
8. **Recommend next steps** for Tier 2 and write a Splunk detection query

It also treats log content as untrusted data, since attackers control fields like command lines and file names.

## Repository layout

```
splunk-alert-triage/
  SKILL.md                              The triage workflow and rules
  references/windows-event-reference.md Security, System, and Sysmon event IDs, plus Sysmon 10 access values
  references/suspicious-patterns.md     Command line patterns mapped to ATT&CK, and expected side effects
  templates/triage-report.md            The report format
examples/
  esentutl-sam-copy-report.md           A full report from the OTRF SAM copy dataset
detections/
  sam_hive_copy.spl                     The tested Splunk detection from that report
```

## Example

Run against the [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) `cmd_sam_copy_esentutl` capture (915 events), the skill produced [this report](examples/esentutl-sam-copy-report.md). The short version:

- **Decision:** Escalate. **Severity:** High. **Confidence:** High.
- **What happened:** A user ran `esentutl.exe /y /vss` to copy the SAM registry hive, which stores local password hashes, out of a shadow copy to `C:\ProgramData\SAM`.
- **Noise ruled out:** 188 Sysmon process access events where lsass.exe opened other processes with routine `0x1000` rights, 186 group enumeration events caused by Volume Shadow Copy, and log clearing that happened before the attack started.

## What I learned

Building this skill caught a mistake in my own earlier analysis. In my SIEM lab, I treated lsass.exe opening esentutl.exe as evidence of the attack, and I built an alert on Event ID 4663 for SAM file access. When I worked through the data with this triage process:

- The lsass.exe events were routine. lsass.exe was the **source** with low-level `0x1000` rights. Credential dumping from memory looks like the reverse: something opening lsass.exe with read access.
- The only 4663 event was a read of the `Lsa` registry key, not the SAM file, so my original alert query matched zero events.
- The real evidence was the esentutl command line and the SAM file it created.

I rewrote the detection to match on those two sources and tested it against the dataset. It now returns exactly the three attack events with no false positives. The lesson for me was that a detection is only as good as your understanding of the actual field values, and that a structured triage process is valuable precisely because it makes you check your assumptions.

## How to use it

- **Claude Code:** copy the `splunk-alert-triage` folder into `~/.claude/skills/`.
- **Claude app:** zip the `splunk-alert-triage` folder and upload it as a custom skill.

Then give Claude a Splunk export or log file and ask it to triage the events.

## Tools and concepts

Claude skills, Splunk SPL, Windows Security and Sysmon event logs, MITRE ATT&CK, SOC triage and escalation, detection engineering
