# SPL Query Notebook

Practical SPL queries used while building and investigating the Mini SOC.

## 1. Count events by sourcetype

```spl
index=windows
| stats count by sourcetype
| sort - count
```

## 2. Count Sysmon events by Event ID

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\d+)</EventID>"
| stats count by EventID
| sort - count
```

## 3. Process creation baseline

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search EventID=1
| stats count by Image
| sort - count
```

## 4. Processes by user

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex "<Data Name='User'>(?<User>[^<]+)</Data>"
| search EventID=1
| stats count by User Image
| sort - count
```

## 5. Rare process hunting

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search EventID=1
| rare Image limit=10
```

## 6. Process-injection relationship hunting

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name='SourceImage'>(?<SourceImage>[^<]+)</Data>"
| rex "<Data Name='TargetImage'>(?<TargetImage>[^<]+)</Data>"
| search EventID=8
| stats count by SourceImage TargetImage
| sort - count
```

## 7. Event volume over time

```spl
index=windows
| timechart count span=1h
```

## 8. Sysmon volume over time

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| timechart count span=1h
```

## Investigation pattern

```text
Discover -> filter -> extract -> aggregate -> correlate -> investigate -> assess
```

The purpose of these queries is to understand the endpoint's normal behavior before deciding what deserves a detection.
