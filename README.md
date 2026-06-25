# home-soc-lab
Home SOC lab: Splunk SIEM, Sysmon, and MITRE ATT&amp;CK detections.
# Home SOC Lab — Detection Engineering with Splunk, Sysmon & MITRE ATT&CK

A hands-on Security Operations Center (SOC) lab built to practice the core
workflow of a SOC analyst: ingesting endpoint logs into a SIEM, simulating
adversary techniques, writing detections, and triaging the resulting alerts.

> Status: 🚧 In progress — building out log ingestion. Detections coming next.

---

## Objective

Stand up a working detection pipeline from scratch and demonstrate, for several
real attack techniques, the full path from **attack → log evidence → detection
→ triage**.

## Architecture

```
┌─────────────────────────┐         logs on :9997        ┌──────────────────────┐
│  Windows 10 VM (victim)  │ ───────────────────────────▶ │  Splunk (SIEM)        │
│  Sysmon + Universal Fwdr │   Security + Sysmon events    │  Search & detections  │
│  (VirtualBox, Mac host)  │                               │  (separate Mac)       │
└─────────────────────────┘                               └──────────────────────┘
```

| Component | Tool |
|---|---|
| Hypervisor | Oracle VirtualBox |
| Victim endpoint | Windows 10 (64-bit) VM |
| Endpoint logging | Sysmon (SwiftOnSecurity config) |
| Log shipping | Splunk Universal Forwarder |
| SIEM | Splunk (Free) |
| Attack simulation | Atomic Red Team |
| Detection framework | MITRE ATT&CK |

## Log sources ingested

- Windows Security event log (logons, account management)
- Sysmon Operational log (process creation, network, etc.)
- Windows System event log

*(Screenshot: logs arriving in Splunk — `screenshots/log-ingestion.png`)*

---

## Detections

> Coming soon. For each technique I'll document: the attack run, the MITRE
> technique ID, the Splunk search (SPL) that catches it, a screenshot of the
> detection firing, and triage notes.

| # | Technique | MITRE ID | Status |
|---|---|---|---|
| 1 | Brute-force login | T1110 | ⬜ Planned |
| 2 | Encoded PowerShell | T1059.001 | ⬜ Planned |
| 3 | New local account created | T1136 | ⬜ Planned |
| 4 | LOLBin download (certutil) | T1105 | ⬜ Planned |

### Example detection format (to be filled in)

**T1110 — Brute Force**

- *Attack:* repeated failed logins against the victim, followed by a success.
- *Detection (SPL):*
  ```
  index=main source="WinEventLog:Security" EventCode=4625
  | stats count by Account_Name, Source_Network_Address
  | where count > 5
  ```
- *Evidence:* `screenshots/t1110-detection.png`
- *Triage:* [true/false positive? next investigative step — check for a
  following 4624 success, source IP, account targeted, recommended response.]

---

## What I learned

*(Fill in as you go — e.g. how Sysmon enriches Windows logging, how forwarders
ship data, how detections map to ATT&CK, networking gotchas you solved.)*
