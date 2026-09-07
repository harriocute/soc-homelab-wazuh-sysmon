# Splunk Detection Catalog

## D01 — Possible Brute-Force Authentication

**Status:** Validated  
**Data source:** Windows Security Event Log  
**Primary event:** 4625 (failed logon)  
**Threshold:** 5 or more failures for the same account/source within a five-minute bucket.  
**Schedule:** Every 5 minutes  
**Response:** Splunk Triggered Alerts  

### SPL

```spl
index=windows sourcetype="XmlWinEventLog:Security" "4625"
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex "<Data Name='IpAddress'>(?<SourceIP>[^<]+)</Data>"
| rex "<Data Name='LogonType'>(?<LogonType>[^<]+)</Data>"
| bin _time span=5m
| stats count values(LogonType) as LogonType by _time host TargetUserName SourceIP
| where count >= 5
| sort - _time
```

### Validation

A controlled test generated five failed logons. The search identified the activity and the scheduled Splunk alert was subsequently observed in Triggered Alerts.

Because the test was local, the source address was `127.0.0.1`; this was treated as a lab simulation rather than evidence of an external brute-force attack.

### False positives

- Repeated incorrect password entry
- Services/applications using stale credentials
- Authorized security testing
- Local lab testing

---

## D02 — Suspicious PowerShell Execution

**Status:** Validated  
**Data source:** Sysmon  
**Primary event:** Event ID 1 (Process Creation)  
**Condition:** Actual Windows PowerShell process using `-ExecutionPolicy Bypass`, excluding Splunk's `splunk-powershell.exe`.  
**Schedule:** Every 5 minutes  
**Response:** Splunk Triggered Alerts  

### SPL

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex "<Data Name='User'>(?<User>[^<]+)</Data>"
| rex "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex "<Data Name='ParentCommandLine'>(?<ParentCommandLine>[^<]+)</Data>"
| rex "<Data Name='IntegrityLevel'>(?<IntegrityLevel>[^<]+)</Data>"
| search EventID=1
| search Image="*powershell.exe"
| search NOT Image="*splunk-powershell.exe"
| search CommandLine="*-ExecutionPolicy Bypass*"
| table _time host User Image CommandLine ParentImage ParentCommandLine IntegrityLevel
| sort - _time
```

### Validation

A harmless controlled PowerShell command was executed using `-NoProfile -ExecutionPolicy Bypass`. Sysmon recorded the process creation, the Universal Forwarder sent it to Splunk, the SPL matched it, and the scheduled alert appeared in Triggered Alerts.

### Analyst note

`ExecutionPolicy Bypass` is an investigation indicator, not proof of malicious activity. Analysts should consider the user, parent process, command line, integrity level, and surrounding events.

### False positives

- Authorized administration
- Software deployment
- Troubleshooting
- Security testing
- Controlled lab activity
