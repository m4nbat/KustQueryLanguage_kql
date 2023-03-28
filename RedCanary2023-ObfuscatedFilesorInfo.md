# Red Canary Threat Report - Obfuscated Files and Information

**Source:** https://redcanary.com/threat-detection-report/techniques/obfuscated-files-information/

**Experimental hunting queries based on Red Canary threat report (Untested)**

## Detecting Base64 encoding
If you’re looking to detect malicious use of Base64 encoding, consider monitoring for the execution of processes like powershell.exe or cmd.exe along with command lines containing parameters like ToBase64String and FromBase64String.


**Pseudocode:** process == ('powershell.exe' || 'cmd.exe') && command_includes ('base64')

**Kusto:**
`TBA`


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

`DeviceProcessEvents | where InitiatingProcessFileName endswith "cmd.exe" or FileName endswith "cmd.exe" | extend a = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','^') | extend b = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','=') | extend c = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','%') | extend d = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','!') | extend e = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','[') | extend f = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt','(') | extend g = countof(@'InitiatingProcessCommandLine" > tweet.txt & type tweet.txt',';') | extend suspiciousChars = a + b + c + d + e + f + g | where suspiciousChars > 4`


## ZIP file spawning JavaScript
We’ve detected high volumes of obfuscation this year looking for apparent phishing schemes where adversaries conceal JavaScript payloads in ZIP files and write them to the users and temp directories.

**Pseudocode:**  process == 'wscript.exe' && command_includes ('users' && 'temp' && '.zip’ && '.js') &&
has_external_netconn

**Kusto:**

`DeviceNetworkEvents
| where InitiatingProcessFileName =~ "wscript.exe" and InitiatingProcessCommandLine has_any ('users','temp') and InitiatingProcessCommandLine has_any ('.zip','.js') and ipv4_is_private(RemoteIP) == false`

`DeviceFileEvents
| where ActionType =~ "FileCreated" and FolderPath has_any ("temp","users") and FileName endswith ".js"`

