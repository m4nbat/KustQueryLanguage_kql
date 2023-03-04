# ChromeLoader Hunt Queries
# Source: https://redcanary.com/blog/chromeloader/

## PowerShell containing a shortened version of the encodedCommand flag in its command line (Decrypt Base 64 commandlines)
`//PowerShell containing a shortened version of the encodedCommand flag in its command line
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
//| where DecodedString contains "$" // uncomment this line to look for multiple variables being used paired with the use of the encoded command.`

## PowerShell containing a shortened version of the encodedCommand flag in its command line 
`//Chromeloader: PowerShell containing a shortened version of the encodedCommand flag in its command line
//Note: Many applications will legitimately encode PowerShell and make use of these shortened flags. Some tuning may be required, depending on your environment. To refine this detection analytic, consider looking for multiple variables in the decoded PowerShell block paired with the use of a shortened encodedCommand flag stated above. Variables are declared in PowerShell using $.
//this detection logic looks for the execution of encoded PowerShell commands. Not all encoded PowerShell is malicious, but encoded commands are worth keeping an eye on.
//https://redcanary.com/blog/chromeloader/
DeviceProcessEvents 
| where ((InitiatingProcessFileName =~ "powershell.exe" and InitiatingProcessCommandLine has_any ("-e","-en","-enc","-enco","-ecod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")) or (FileName =~ "powershell.exe" and ProcessCommandLine has_any ("-e","-en","-enc","-enco","-ecod","-encode","-encoded","-encodedc","-encodedco","-encodedcom","-encodedcomm","-encodedcomma","-encodedcomman","-encodedcommand")))
//| where InitiatingProcessCommandLine contains "$" or ProcessCommandLine contains "$" // uncomment this line to look for multiple variables being used paired with the use of the encoded command.`

# PowerShell spawning chrome.exe containing load-extension and AppData\Local within the command line
`//Chromeloader: PowerShell spawning chrome.exe containing load-extension and AppData\Local within the command line
//The detection analytic looks for instances of the Chrome browser executable spawning from PowerShell with a corresponding command line that includes appdata\local as a parameter.
DeviceProcessEvents 
| where (InitiatingProcessFileName =~ "powershell.exe" and FileName =~ "chrome.exe" and ProcessCommandLine has_any ("AppData\\Local,load-extension")) or (InitiatingProcessParentFileName =~ "powershell.exe" and InitiatingProcessFileName =~ "chrome.exe" and InitiatingProcessCommandLine has_any ("AppData\\Local,load-extension"))`

# PowerShell spawning chrome.exe containing load-extension and AppData\Local within the command line
`//Chromeloader: PowerShell spawning chrome.exe containing load-extension and AppData\Local within the command line
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
| where (InitiatingProcessFileName =~ "powershell.exe" and FileName =~ "chrome.exe" and DecodedString  has_any ("AppData\\Local,load-extension")) or (InitiatingProcessParentFileName =~ "powershell.exe" and InitiatingProcessFileName =~ "chrome.exe" and InitiatingDecodedString has_any ("AppData\\Local,load-extension"))`

# Shell process spawning process loading a Chrome extension within the command line
`//Chromeloader: Shell process spawning process loading a Chrome extension within the command line
//This analytic looks for sh or bash scripts running in macOS environments with command lines associated with the macOS variant of ChromeLoader.
DeviceProcessEvents 
| where (InitiatingProcessFileName has_any ("sh","bash") and FileName =~ "chrome.exe" and ProcessCommandLine has_any ("/tmp/","load-extension","chrome")) or (InitiatingProcessParentFileName has_any ("sh","bash") and InitiatingProcessFileName =~ "chrome.exe" and InitiatingProcessCommandLine has_any ("/tmp/","load-extension","chrome"))`

# MacOS - Redirected Base64 encoded commands into a shell process
`//Chromeloader: MacOS - Redirected Base64 encoded commands into a shell process
//Like the encoded PowerShell detection analytics idea, this detector looks for the execution of encoded sh, bash, or zsh commands on macOS endpoints.
//Note: As is the case with PowerShell, there are many legitimate uses for encoding shell commands. Some tuning may be required, depending on your environment.
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any ("echo","base64") and FileName has_any ("sh","bash","zsh")`
