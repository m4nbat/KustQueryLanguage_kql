# ChromeLoader Hunt Queries

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1176 | Browser Extensions | [Browser Extensions](https://attack.mitre.org/techniques/T1176/) |
| T1059.001 | Command and Scripting Interpreter: PowerShell | [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| T1140 | Deobfuscate/Decode Files or Information | [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/) |

#### Description
Hunt queries for ChromeLoader, a persistent browser hijacker and adware that uses PowerShell to inject itself into the Chrome browser as a malicious extension. ChromeLoader uses Base64-encoded PowerShell commands to load a malicious Chrome extension from AppData, modifying browser settings and redirecting search traffic. A macOS variant also exists that uses shell scripts.

#### Risk
ChromeLoader can redirect user search traffic, inject advertisements, and potentially deliver more dangerous payloads. Its use of encoded PowerShell commands and Chrome extension mechanisms makes it difficult to detect with standard endpoint tools.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://redcanary.com/blog/chromeloader/

## Defender For Endpoint

### PowerShell containing a shortened version of the encodedCommand flag in its command line (Decrypt Base64 commandlines)
```KQL
//PowerShell containing a shortened version of the encodedCommand flag in its command line
//PowerShell Base64 encoding
// This query will identify strings in process command lines which match Base64 encoding format, extract the string to a column called Base64, and decode it in a column called DecodedString.
//Note: Many applications will legitimately encode PowerShell and make use of these shortened flags. Some tuning may be required, depending on your environment. To refine this detection analytic, consider looking for multiple variables in the decoded PowerShell block paired with the use of a shortened encodedCommand flag stated above. Variables are declared in PowerShell using $.
//https://redcanary.com/blog/chromeloader/
DeviceProcessEvents 
| extend SplitLaunchString = split(ProcessCommandLine, " ")
| mvexpand SplitLaunchString
| where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString)
| extend DecodedString = base64_decodestring(Base64)
| where isnotempty(DecodedString)
| extend SplitLaunchString1 = split(InitiatingProcessCommandLine, " ")
| mvexpand SplitLaunchString1
| where SplitLaunchString1 matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString1)
| extend InitiatingDecodedString = base64_decodestring(Base64)
| where isnotempty(InitiatingDecodedString)
| where InitiatingProcessParentFileName !in~ ("SenseIR.exe")
| where ((InitiatingProcessFileName =~ "powershell.exe" and InitiatingDecodedString has_any ("-e","-en","-enc","-enco","-ecod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")) or (FileName =~ "powershell.exe" and DecodedString has_any ("-e","-en","-enc","-enco","-ecod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")))
//| where DecodedString contains "$" // uncomment this line to look for multiple variables being used paired with the use of the encoded command.
```

### PowerShell containing a shortened version of the encodedCommand flag in its command line
```KQL
//Chromeloader: PowerShell containing a shortened version of the encodedCommand flag in its command line
//Note: Many applications will legitimately encode PowerShell and make use of these shortened flags. Some tuning may be required, depending on your environment. To refine this detection analytic, consider looking for multiple variables in the decoded PowerShell block paired with the use of a shortened encodedCommand flag stated above. Variables are declared in PowerShell using $.
//this detection logic looks for the execution of encoded PowerShell commands. Not all encoded PowerShell is malicious, but encoded commands are worth keeping an eye on.
//https://redcanary.com/blog/chromeloader/
DeviceProcessEvents 
| where ((InitiatingProcessFileName =~ "powershell.exe" and InitiatingProcessCommandLine has_any ("-e","-en","-enc","-enco","-ecod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")) or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-e","-en","-enc","-enco","-ecod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")))
//| where InitiatingProcessCommandLine contains "$" or ProcessCommandLine contains "$" // uncomment this line to look for multiple variables being used paired with the use of the encoded command.
```

### PowerShell spawning chrome.exe containing load-extension and AppData\Local within the command line
```KQL
//Chromeloader: PowerShell spawning chrome.exe containing load-extension and AppData\Local within the command line
//The detection analytic looks for instances of the Chrome browser executable spawning from PowerShell with a corresponding command line that includes appdata\local as a parameter.
DeviceProcessEvents 
| where (InitiatingProcessFileName =~ "powershell.exe" and FileName =~ "chrome.exe" and ProcessCommandLine has_any ("AppData\\Local,load-extension")) or (InitiatingProcessParentFileName =~ "powershell.exe" and InitiatingProcessFileName =~ "chrome.exe" and InitiatingProcessCommandLine has_any ("AppData\\Local,load-extension"))
```

### PowerShell spawning chrome.exe with Base64 decoded command line
```KQL
//Chromeloader: PowerShell spawning chrome.exe containing load-extension and AppData\Local within the command line
//The detection analytic looks for instances of the Chrome browser executable spawning from PowerShell with a corresponding command line that includes appdata\local as a parameter.
DeviceProcessEvents 
| extend SplitLaunchString = split(ProcessCommandLine, " ")
| mvexpand SplitLaunchString
| where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString)
| extend DecodedString = base64_decodestring(Base64)
| where isnotempty(DecodedString)
| extend SplitLaunchString1 = split(InitiatingProcessCommandLine, " ")
| mvexpand SplitLaunchString1
| where SplitLaunchString1 matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString1)
| extend InitiatingDecodedString = base64_decodestring(Base64)
| where isnotempty(InitiatingDecodedString)
| where (InitiatingProcessFileName =~ "powershell.exe" and FileName =~ "chrome.exe" and DecodedString  has_any ("AppData\\Local,load-extension")) or (InitiatingProcessParentFileName =~ "powershell.exe" and InitiatingProcessFileName =~ "chrome.exe" and InitiatingDecodedString has_any ("AppData\\Local,load-extension"))
```

### Shell process spawning process loading a Chrome extension within the command line
```KQL
//Chromeloader: Shell process spawning process loading a Chrome extension within the command line
//This analytic looks for sh or bash scripts running in macOS environments with command lines associated with the macOS variant of ChromeLoader.
DeviceProcessEvents 
| where (InitiatingProcessFileName has_any ("sh","bash") and FileName =~ "chrome.exe" and ProcessCommandLine has_any ("/tmp/","load-extension","chrome")) or (InitiatingProcessParentFileName has_any ("sh","bash") and InitiatingProcessFileName =~ "chrome.exe" and InitiatingProcessCommandLine has_any ("/tmp/","load-extension","chrome"))
```

### MacOS - Redirected Base64 encoded commands into a shell process
```KQL
//Chromeloader: MacOS - Redirected Base64 encoded commands into a shell process
//Like the encoded PowerShell detection analytics idea, this detector looks for the execution of encoded sh, bash, or zsh commands on macOS endpoints.
//Note: As is the case with PowerShell, there are many legitimate uses for encoding shell commands. Some tuning may be required, depending on your environment.
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any ("echo","base64") and FileName has_any ("sh","bash","zsh")
```
