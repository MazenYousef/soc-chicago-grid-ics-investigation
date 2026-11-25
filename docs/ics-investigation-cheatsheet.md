# ICS / OT Investigation Cheatsheet

Quick reference built while working this case.

## IT vs OT: what changes for the analyst

| | Corporate IT | OT / ICS (SCADA, PLC, HMI) |
|---|---|---|
| Priority | Confidentiality | **Safety and availability** |
| Patching | Monthly | Rare; legacy systems common |
| Typical response | Isolate the host immediately | Coordinate with operations: isolation can stop a physical process |
| Impact of compromise | Data loss | **Physical outage, equipment damage, danger to life** |
| Standards | ISO 27001, NIST CSF | **IEC 62443**, NERC CIP; in Germany **BSI KRITIS**, NIS2 |

## Key terms

- **SCADA**: supervisory control and data acquisition. Central monitoring and control of distributed industrial assets (substations, pipelines).
- **HMI**: human-machine interface. The operator's screen into the process.
- **PLC / RTU**: field controllers that actually open breakers and drive valves.
- **Purdue model**: layered reference architecture (Level 0 field devices → Level 4/5 enterprise IT). Traffic should cross levels only through controlled conduits and a DMZ.

## Hunting patterns used

| Goal | Pattern |
|---|---|
| Start from the impact | `ProcessEvents \| where process_commandline has "SCADA"` |
| Find patient zero | `summarize min(timestamp), dcount(hostname)` on the malware name; a low host count marks the first victim |
| User vs exploit | Parent `Explorer.exe` = the user opened it; `winword.exe`, `outlook.exe` = a document or email |
| Delivery | `OutboundNetworkEvents` for the host IP in the minutes before first execution |
| Campaign size | `Email \| where subject contains "<lure>" \| summarize count() by sender` |
| Infrastructure | `PassiveDns`: domain → IP → other domains |
| Recon | `InboundNetworkEvents` from actor IPs to your own website |
| Account takeover | `AuthenticationEvents \| where src_ip in (actor_ips)` |

## High-signal command lines

| Command | Why it matters |
|---|---|
| `psexec \\host -u administrator -p …` in a `for` loop | Scripted lateral movement with one shared credential |
| `nltest /dclist:<domain>` | Domain-controller discovery |
| `wevtutil cl <log>` | Event-log clearing (anti-forensics) |
| `curl -o … http://…` on a workstation | Tool or payload download |
| Scanners with `--type SCADA` / OT ranges | ICS discovery before attack |
| `KillDisk`, `--wipe` | Destructive wiper |

## Sandworm (APT44 / Seashell Blizzard) in brief

- Russian GRU Unit 74455.
- **2015** Ukraine grid attack: BlackEnergy, then manual breaker operation, then KillDisk. About 225,000 customers lost power.
- **2016** Industroyer / CrashOverride (Kyiv); **2017** NotPetya; **2022** Industroyer2 and wipers during the invasion of Ukraine.
- Pattern: long IT intrusion → OT access → destructive impact timed for maximum effect, combined with wipers to slow recovery.
