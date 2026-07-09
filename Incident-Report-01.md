# Incident Report #01 — Simulated Multi-Stage Intrusion

**Analyst:** Kostas Markopoulos
**Date:** 2026-07-06
**Host:** DESKTOP-IDMRUOJ
**Affected account:** DESKTOP-IDMRUOJ\mikapa
**Environment:** Home SOC lab (Windows 11 ARM VM, Sysmon + Splunk)
**Classification:** True Positive
**Severity:** High / Critical

---

## 1. Summary

An endpoint alert fired for suspicious access to `lsass.exe` on host
DESKTOP-IDMRUOJ. Investigation confirmed a multi-stage intrusion executed under
the `mikapa` user context: the attacker ran discovery commands, attempted to
dump LSASS process memory to steal credentials, and established persistence via
a scheduled task. This is assessed as a **true positive** with **high severity**
due to the combination of credential-access and persistence activity, which
together indicate an attacker attempting to maintain and expand access.

## 2. Investigation notes

The initial alert (Sysmon EventCode 10, ProcessAccess to lsass) did not return
results on first search. Rather than close the alert, the investigation pivoted
to **process-creation events (EventCode 1)** and identified the credential-dump
tooling by its command line (`rundll32.exe ... comsvcs.dll, MiniDump`). A host +
time-window timeline was then built and filtered to the `mikapa` account
(excluding forwarder/SYSTEM noise) to reconstruct the full attack sequence.

> Detection-coverage note: EventCode 10 (ProcessAccess) was not available in the
> current Sysmon config. Corroborating evidence in the process-creation log
> confirmed the activity regardless — a reminder to tune Sysmon to capture
> ProcessAccess for LSASS in production.

## 3. Timeline of attacker activity

| Time (approx) | Action | Command / Evidence | MITRE |
|---|---|---|---|
| 18:39:41 | Command shell opened | `cmd.exe` (parent `explorer.exe`) | — |
| 18:39:44 | PowerShell spawned PowerShell | `powershell -Command Start-Process powershell ...` | T1059.001 |
| 18:39:48 | Host/user discovery | `whoami` | T1033 |
| 18:39:59 | Account enumeration | `net user` / `net1 user` | T1087 |
| 18:40:43 | Located LSASS process | `tasklist`, `findstr lsass` | T1057 |
|  18:43:13 | LSASS memory dump attempt | `rundll32 comsvcs.dll, MiniDump <PID> lsass.dmp` | T1003.001 |
|  18:44:23 | Persistence established | `schtasks /create /tn "Updater" ... /ru System` | T1053.005 |

*(Adjust exact timestamps to match your Splunk results.)*

## 4. MITRE ATT&CK techniques observed

- **T1059.001** — Command and Scripting Interpreter: PowerShell (execution)
- **T1033 / T1087 / T1057** — Discovery (user, account, and process discovery)
- **T1003.001** — OS Credential Dumping: LSASS Memory (credential access)
- **T1053.005** — Scheduled Task/Job (persistence)

## 5. Impact and scope

- **Credential access attempted** against LSASS — any credentials cached on this
  host should be considered potentially compromised.
- **Persistence established** — a scheduled task (`Updater`) set to run as SYSTEM
  at logon, giving the attacker a recurring foothold.
- Activity confined to a single host and the `mikapa` account in this
  investigation; a real incident would require checking other hosts for the same
  indicators (lateral movement).

## 6. Recommended actions

1. **Contain:** isolate DESKTOP-IDMRUOJ from the network.
2. **Eradicate persistence:** delete the malicious scheduled task
   (`schtasks /delete /tn "Updater" /f`).
3. **Credentials:** force a password reset for accounts used on this host, as
   LSASS access may have exposed cached credentials.
4. **Account review:** investigate the `mikapa` account for compromise and review
   any accounts created during the incident.
5. **Hunt:** search other hosts for the same indicators (comsvcs MiniDump command
   lines, the `Updater` scheduled task, the discovery command burst).
6. **Detection improvement:** enable Sysmon EventCode 10 (ProcessAccess) with an
   LSASS filter so future credential-dump attempts alert directly.

## 7. Verdict

**True Positive — High/Critical severity.** A coordinated sequence of execution,
discovery, credential access, and persistence on a single host. Recommended for
escalation and host containment.
