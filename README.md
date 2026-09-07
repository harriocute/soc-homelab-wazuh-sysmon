# SOC Home Lab - Wazuh, Sysmon & Splunk

## Overview

This project demonstrates the design and implementation of a practical Security Operations Center (SOC) home lab using Wazuh, Sysmon, and Splunk.

The lab focuses on endpoint monitoring, threat detection, alert investigation, threat hunting, and detection engineering using Windows telemetry.

---

## Objectives

- Deploy functional SIEM/SOC tooling.
- Monitor Windows endpoint activity using Sysmon.
- Investigate Windows security events.
- Build and validate custom detections.
- Practice SPL-based threat hunting with Splunk.
- Map relevant detections to the MITRE ATT&CK framework where appropriate.
- Develop practical SOC analyst skills.

---

## Lab Environment

| Component | Technology |
|-----------|------------|
| SIEM / SOC tooling | Wazuh 4.14.5, Splunk Enterprise |
| Endpoint | Windows 11 |
| Endpoint monitoring | Sysmon |
| Agents / forwarders | Wazuh Agent, Splunk Universal Forwarder |
| Server | Ubuntu Linux |
| Virtualization | Oracle VirtualBox |

---

## Skills Demonstrated

- SIEM Deployment
- Windows Event Analysis
- Threat Hunting
- Alert Investigation
- Detection Engineering
- Sysmon Monitoring
- PowerShell Analysis
- SPL / Splunk Investigation
- False-Positive Analysis
- MITRE ATT&CK Mapping
- Security Operations

---

## Repository Structure

```text
architecture/
investigations/
rules/
screenshots/
splunk/
README.md
```

### Splunk Mini SOC

The [`splunk/`](splunk/) directory contains the dedicated Splunk Mini SOC project documentation, including:

- architecture and telemetry overview
- practical SPL queries
- two validated Splunk detections
- threat-hunting investigations
- alert validation methodology

See [`splunk/README.md`](splunk/README.md), [`splunk/SPL-QUERIES.md`](splunk/SPL-QUERIES.md), and [`splunk/DETECTIONS.md`](splunk/DETECTIONS.md).

---

## Project Status

🚧 In Progress

This repository is continuously updated as new detections, investigations, and custom rules are developed.
