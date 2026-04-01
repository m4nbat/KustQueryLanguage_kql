# Catch In-Memory Loading of Hack Tools

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1620 | Reflective Code Loading | [Reflective Code Loading](https://attack.mitre.org/techniques/T1620/) |

#### Description
Detects in-memory loading of known offensive security tools and post-exploitation frameworks (e.g., Rubeus, SharpHound, Seatbelt, Mimikatz variants) via CLR unbacked module loads in PowerShell. These tools are commonly delivered via C2 frameworks like Cobalt Strike after initial access.

#### Risk
In-memory loading of hack tools via PowerShell's CLR bypasses traditional file-based AV/EDR detection. Detection of CLR unbacked module loads matching known offensive tool names indicates active post-exploitation activity, potentially including credential theft, lateral movement, or privilege escalation.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- Recent Purple Team

## Defender For Endpoint
```KQL
let iocList = dynamic ([
"BOFNET",
"SharpUp",
"ReflectedDelegate",
'ADCollector',
'ADCSPwn',
'ADSearch',
'ADFSDump',
'AtYourService',
'BetterSafetyKatz',
'Certify',
'EDD',
'ForgeCert',
'DeployPrinterNightmare',
'Grouper2',
'Group3r',
'KrbRelay',
'KrbRelayUp',
'InveighZero',
'LockLess',
'PassTheCert',
'PurpleSharp',
'Rubeus',
'SafetyKatz',
'SauronEye',
'scout',
'SearchOutlook',
'Seatbelt',
'Sharp-SMBExec',
'SharpAllowedToAct',
'SharpAppLocker',
'SharpBlock',
'SharpBypassUAC',
'SharpChisel',
'SharpChrome',
'SharpChromium',
'SharpCloud',
'SharpCOM',
'SharpCrashEventLog',
'SharpDir',
'SharpDoor',
'SharpDPAPI',
'SharpDump',
'SharpEDRChecker',
'SharpExec',
'SharPersist',
'SharpFiles',
'SharpGPOAbuse',
'SharpHandler',
'SharpHose',
'SharpHound',
'SharpKatz',
'SharpLaps',
'SharpMapExec',
'SharpMiniDump',
'SharpMove',
'SharpPrinter',
'SharpNoPSExec',
'SharpRDP',
'SharpReg',
'SharpSCCM',
'SharpSecDump',
'SharpShares',
'SharpSphere',
'SharpSpray',
'SharpStay',
'SharpSvc',
'SharpSniper',
'SharpSQLPwn',
'SharpTask',
'SharpUp',
'SharpView',
'SharpWMI',
'SharpWebServer',
'SharpWifiGrabber',
'SharpZeroLogon',
'Shhmon',
'Snaffler',
'SqlClient',
'StandIn',
'StickyNotesExtract',
'SweetPotato',
'ThunderFox',
'TruffleSnout',
'TokenStomp',
'Watson',
'winPEAS',
'WMIReg',
'Whisker'
]);
DeviceEvents
| extend module = parse_json(AdditionalFields).ModuleILPathOrName
| where ActionType =~ "ClrUnbackedModuleLoaded" and module in~ (iocList) and InitiatingProcessFileName =~ "powershell.exe"
```

## Sentinel
```KQL
let iocList = dynamic ([
"BOFNET",
"SharpUp",
"ReflectedDelegate",
'ADCollector',
'ADCSPwn',
'ADSearch',
'ADFSDump',
'AtYourService',
'BetterSafetyKatz',
'Certify',
'EDD',
'ForgeCert',
'DeployPrinterNightmare',
'Grouper2',
'Group3r',
'KrbRelay',
'KrbRelayUp',
'InveighZero',
'LockLess',
'PassTheCert',
'PurpleSharp',
'Rubeus',
'SafetyKatz',
'SauronEye',
'scout',
'SearchOutlook',
'Seatbelt',
'Sharp-SMBExec',
'SharpAllowedToAct',
'SharpAppLocker',
'SharpBlock',
'SharpBypassUAC',
'SharpChisel',
'SharpChrome',
'SharpChromium',
'SharpCloud',
'SharpCOM',
'SharpCrashEventLog',
'SharpDir',
'SharpDoor',
'SharpDPAPI',
'SharpDump',
'SharpEDRChecker',
'SharpExec',
'SharPersist',
'SharpFiles',
'SharpGPOAbuse',
'SharpHandler',
'SharpHose',
'SharpHound',
'SharpKatz',
'SharpLaps',
'SharpMapExec',
'SharpMiniDump',
'SharpMove',
'SharpPrinter',
'SharpNoPSExec',
'SharpRDP',
'SharpReg',
'SharpSCCM',
'SharpSecDump',
'SharpShares',
'SharpSphere',
'SharpSpray',
'SharpStay',
'SharpSvc',
'SharpSniper',
'SharpSQLPwn',
'SharpTask',
'SharpUp',
'SharpView',
'SharpWMI',
'SharpWebServer',
'SharpWifiGrabber',
'SharpZeroLogon',
'Shhmon',
'Snaffler',
'SqlClient',
'StandIn',
'StickyNotesExtract',
'SweetPotato',
'ThunderFox',
'TruffleSnout',
'TokenStomp',
'Watson',
'winPEAS',
'WMIReg',
'Whisker'
]);
DeviceEvents
| extend module = parse_json(AdditionalFields).ModuleILPathOrName
| where ActionType =~ "ClrUnbackedModuleLoaded" and module in~ (iocList) and InitiatingProcessFileName =~ "powershell.exe"
```
