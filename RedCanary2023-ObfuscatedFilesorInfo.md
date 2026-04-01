# Red Canary 2023: Obfuscated Files or Information Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1027 | Obfuscated Files or Information | [Obfuscated Files](https://attack.mitre.org/techniques/T1027/) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell](https://attack.mitre.org/techniques/T1059/001/) |

#### Description
Detection queries based on the Red Canary 2023 threat report for obfuscated files or information. Covers PowerShell -EncodedCommand switch, escape character obfuscation in cmd.exe, and ZIP files spawning JavaScript.

#### Risk
Obfuscation is heavily used by adversaries to evade detection. PowerShell encoded commands, escape character obfuscation, and JavaScript payloads in ZIP files are all common methods used across multiple threat groups.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/threat-detection-report/techniques/obfuscated-files-information/

## Defender For Endpoint
```KQL
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-e","-en","-enc","-enco","-encod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")
```

```KQL
^= % ! [ ( ;.

**Pseudocode:**  process == cmd.exe && command_includes [excessive use of the following] ('^' || '=' || '%' || '!' || '[' || '(' || ';')

**Kusto:**
```

```KQL
## ZIP file spawning JavaScript
We’ve detected high volumes of obfuscation this year looking for apparent phishing schemes where adversaries conceal JavaScript payloads in ZIP files and write them to the users and temp directories.

**Pseudocode:**  process == 'wscript.exe' && command_includes ('users' && 'temp' && '.zip’ && '.js') &&
has_external_netconn

**Kusto:**
```

## Sentinel
```KQL
DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-e","-en","-enc","-enco","-encod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")
```

```KQL
^= % ! [ ( ;.

**Pseudocode:**  process == cmd.exe && command_includes [excessive use of the following] ('^' || '=' || '%' || '!' || '[' || '(' || ';')

**Kusto:**
```

```KQL
## ZIP file spawning JavaScript
We’ve detected high volumes of obfuscation this year looking for apparent phishing schemes where adversaries conceal JavaScript payloads in ZIP files and write them to the users and temp directories.

**Pseudocode:**  process == 'wscript.exe' && command_includes ('users' && 'temp' && '.zip’ && '.js') &&
has_external_netconn

**Kusto:**
```
