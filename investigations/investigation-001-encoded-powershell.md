# Investigation 001 – Encoded PowerShell Execution

## Alert Summary

| Field | Value |
|-------|-------|
| Rule ID | 100100 |
| Rule Description | PowerShell executed with an encoded command |
| Rule Level | 10 |
| MITRE ATT&CK | T1059.001 |
| Tactic | Execution |
| Technique | PowerShell |

---

## Objective

Determine whether the execution of an encoded PowerShell command represented malicious activity or legitimate administrative testing.

---

## Detection

A custom Wazuh rule was created to detect the use of the following PowerShell arguments:

- `-EncodedCommand`
- `-enc`

The rule successfully generated an alert when the encoded PowerShell command was executed.

---

## Evidence

### User

```
DESKTOP-05LIGD5\Harrycode
```

### Parent Process

```
powershell.exe
```

### Child Process

```
powershell.exe
```

### Command Line

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAbwBjACAATABhAGIAIgA=
```

---

## Investigation

The command was manually executed during laboratory testing to validate a custom Wazuh detection rule.

Analysis confirmed:

- The command was initiated by the authorized lab user.
- The activity was expected.
- No persistence, privilege escalation, or lateral movement followed.
- The encoded command was intentionally used to validate detection capabilities.

---

## MITRE ATT&CK

- **Tactic:** Execution
- **Technique:** T1059.001 – PowerShell

---

## Verdict

**Benign administrative activity.**

The alert correctly detected the use of an encoded PowerShell command. The activity was intentionally generated as part of detection engineering and rule validation.

---

## Lessons Learned

- Encoded PowerShell is frequently used by attackers to evade detection.
- Custom Wazuh rules can identify suspicious PowerShell execution.
- Alert investigation should always include context before determining malicious intent.
