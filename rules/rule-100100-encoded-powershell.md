# Rule 100100 – Encoded PowerShell Detection

## Objective

Detect the execution of PowerShell commands using the `-EncodedCommand` or `-enc` arguments.

---

## Why this rule was created

PowerShell supports executing Base64-encoded commands.

Attackers frequently use this technique to:

- Obfuscate malicious commands
- Evade basic command-line monitoring
- Execute payloads without exposing the original script

Because encoded PowerShell is commonly associated with malicious activity, detecting its execution provides useful visibility during endpoint monitoring.

---

## Detection Logic

The rule looks for the following PowerShell command-line arguments:

- `-EncodedCommand`
- `-enc`

---

## Custom XML Rule

```xml
<rule id="100100" level="10">
  <if_group>sysmon_eid1_detections</if_group>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-encodedcommand)</field>
  <description>PowerShell executed with an encoded command.</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>
```

---

## MITRE ATT&CK

| Field | Value |
|------|------|
| Tactic | Execution |
| Technique | PowerShell |
| ATT&CK ID | T1059.001 |

---

## Test Procedure

The following command was executed to validate the rule:

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAbwBjACAATABhAGIAIgA=
```

---

## Expected Result

The custom Wazuh rule should generate:

- Rule ID: **100100**
- Rule Level: **10**
- Description:

```
PowerShell executed with an encoded command.
```

---

## Outcome

The rule successfully detected the encoded PowerShell execution and generated the expected alert.

This confirms that the custom detection rule is functioning correctly.
