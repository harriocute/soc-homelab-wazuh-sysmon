# Splunk Mini SOC

A hands-on Splunk SOC lab added to the broader Wazuh/Sysmon home-lab project. The project demonstrates Windows telemetry collection, SPL-based investigation, detection engineering, alert validation, baseline analysis, and false-positive assessment.

## Architecture

```text
Windows 11 VM
    |
    | Sysmon
    v
Splunk Universal Forwarder
    |
    | TCP/9997
    v
Splunk Enterprise
    |
    +--> SPL investigations
    +--> Detection searches
    +--> Scheduled alerts
```

The Windows and Splunk VMs communicate over a VirtualBox Host-Only network.

## Telemetry

The Splunk `windows` index contained this 24-hour snapshot during the lab:

| Sourcetype | Events |
|---|---:|
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | 5,393 |
| `XmlWinEventLog:Security` | 629 |
| `XmlWinEventLog:System` | 262 |
| `XmlWinEventLog:Application` | 158 |

Sysmon Event ID distribution from the same snapshot:

| Event ID | Count | Meaning |
|---:|---:|---|
| 1 | 2,992 | Process creation |
| 11 | 1,665 | File creation |
| 13 | 420 | Registry value set |
| 22 | 239 | DNS query |
| 3 | 40 | Network connection |
| 12 | 29 | Registry object create/delete |
| 5 | 13 | Process terminated |
| 8 | 3 | CreateRemoteThread |
| 255 | 2 | Sysmon error |
| 4 | 2 | Sysmon service state change |

> Counts are a lab snapshot and will change as telemetry continues to arrive.

## Validated Detections

### D01 — Possible Brute-Force Authentication

Detects five or more failed Windows logons for the same account and source within a five-minute bucket. A controlled test produced five failed logons and the detection successfully triggered a Splunk scheduled alert.

### D02 — Suspicious PowerShell Execution

Detects Sysmon Process Creation events for actual Windows PowerShell using `-ExecutionPolicy Bypass`, while excluding Splunk's own `splunk-powershell.exe`. A harmless controlled PowerShell command was used to validate the pipeline from Sysmon through the Universal Forwarder to Splunk and the scheduled alert.

## Investigation Work

The lab also demonstrates investigation before escalation:

- OneDrive HTTPS traffic was established as expected baseline activity.
- A `rundll32.exe` network connection was correlated to its Process Creation event using the Sysmon Process GUID. The command line referenced `PcaSvc.dll,PcaPatchSchdTask`, consistent with Windows compatibility/maintenance activity, so no detection was created from that event alone.
- Three Sysmon Event ID 8 events were investigated as potential process-injection indicators. Source/target context was reviewed and no alert was created solely because Event ID 8 occurred.
- `rare` process hunting was used to identify low-frequency processes for contextual investigation.

## SPL Skills Practiced

`search`, `rex`, `table`, `stats`, `sort`, `where`, `bin`, `top`, `rare`, `timechart`, multi-field aggregation, and Process GUID correlation.

## SOC Methodology

```text
Collect telemetry
      -> establish baseline
      -> hunt unusual behavior
      -> extract context
      -> correlate events
      -> assess benign vs suspicious
      -> create detection when justified
      -> validate alert
      -> document findings
```

## Future Work

- DNS hunting
- Windows authentication hunts
- persistence hunting
- process ancestry analysis
- investigation timelines
- dashboards
- alert tuning and false-positive reduction
- additional validated detections
