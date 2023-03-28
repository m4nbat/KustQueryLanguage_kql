# Red Canary Threat Report - Obfuscated Files and Information

**Source:** https://redcanary.com/threat-detection-report/techniques/obfuscated-files-information/

**Experimental hunting queries based on Red Canary threat report (Untested)**

## Detecting Base64 encoding
If you’re looking to detect malicious use of Base64 encoding, consider monitoring for the execution of processes like powershell.exe or cmd.exe along with command lines containing parameters like ToBase64String and FromBase64String.


**Pseudocode:** process == ('powershell.exe' || 'cmd.exe') && command_includes ('base64')

**Kusto:**
TBA


## PowerShell -EncodedCommand switch
Use of the -EncodedCommand PowerShell switch represents the most common form of obfuscation that we detect across the environments we monitor.

**Pseudocode:** process == powershell.exe && command_includes [any variation of the encoded command switch]*

**Kusto:**

`DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-e","-en","-enc","-enco","-encod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")`

## Escape characters
Consider alerting on command lines containing excessive use of characters associated with obfuscation, like `^= % ! [ ( ;.

**Pseudocode:**  process == cmd.exe && command_includes [excessive use of the following] ('^' || '=' || '%' || '!' || '[' || '(' || ';')

**Kusto:**


## ZIP file spawning JavaScript
We’ve detected high volumes of obfuscation this year looking for apparent phishing schemes where adversaries conceal JavaScript payloads in ZIP files and write them to the users and temp directories.

**Pseudocode:**  process == 'wscript.exe' && command_includes ('users' && 'temp' && '.zip’ && '.js') &&
has_external_netconn

**Kusto:**


## 

**Pseudocode:**

**Kusto:**
