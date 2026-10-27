# Triage Report: [Short title]

**Decision:** [Escalate / Monitor / Close]
**Severity:** [Critical / High / Medium / Low]
**Confidence:** [High / Medium / Low]
**Summary:** [One sentence: what happened, on which host, by which user.]

## Scope
- **Time range:** [first event] to [last event]
- **Hosts:** [list]
- **Users:** [list]
- **Log sources:** [present] | **Missing:** [any gaps that limit conclusions]
- **Events reviewed:** [count, with top EventIDs]

## Timeline
| Time | Host | User | Source / EventID | What happened |
|---|---|---|---|---|
| | | | | |

## Key evidence
1. [Event, with the exact field values that matter]
2. [...]

## Noise ruled out
- [Pattern] : [why it is routine or a side effect]

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| [ID Name] | [Event that supports it] |

## Recommended next steps (for Tier 2)
1. [...]
2. [...]

## Detection
```spl
[One Splunk query that would catch this behavior next time]
```
**Why this works:** [One or two sentences.]

## Open questions
- [What the data cannot answer yet]
