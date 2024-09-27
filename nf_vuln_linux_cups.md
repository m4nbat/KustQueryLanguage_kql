# TTP Detection Rule: Hunt queries for scoping the Linux CUPS Vulnerability

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  |  | |

#### Description
Hunt queries for scoping vulnerable devices with the Linux CUPS Vulnerability.

From SANS ISC:
_"CUPS may use "filters", executables that can be used to convert documents. The part responsible ("cups-filters") accepts unverified data that may then be executed as part of a filter operation. An attacker can use this vulnerability to inject a malicious "printer". The malicious code is triggered once a user uses this printer to print a document. This has little or no impact if CUPS is not listening on port 631, and the system is not used to print documents (like most servers). An attacker may, however, be able to trigger the print operation remotely. On the local network, this is exploitable via DNS service discovery. A proof of concept exploit has been made available."_

There is no patch right now. Disable and remove cups-browserd (you probably do not need it anyway). Update CUPS as updates become available. Stop UDP traffic on Port 631.

Related CVE's
- CVE-2024-47176
- CVE-2024-47076
- CVE-2024-47115
- CVE-2024-47177

#### Risk
This vulnerability should be remediated on internet facing devices before proof of concept exploits are released and used in mass exploitation activity by threat actors.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/
  https://isc.sans.edu/diary/Patch%20for%20Critical%20CUPS%20vulnerability%3A%20Don%27t%20Panic/31302

## Defender For Endpoint
```KQL
DeviceTvmSoftwareInventory
| where OSPlatform =~ "Linux"
| where SoftwareName contains "cups"
```
```KQL
let linuxHosts = DeviceInfo
| where OSPlatform =~ "Linux" | distinct DeviceId ;
DeviceNetworkEvents
| where DeviceId in~ (linuxHosts)
| where LocalPort == 631
```

```KQL
//Maybe but untested:
let linuxHosts = DeviceInfo
| where OSPlatform =~ "Linux" | distinct DeviceId ;
let devicesRunning631= DeviceNetworkEvents
| where DeviceId in~ (linuxHosts)
| where RemotePort == 631 or LocalPort == 631
| distinct DeviceName, InitiatingProcessFileName;
DeviceFileEvents
| where DeviceId has_any (devicesRunning631) and ( FileName has_any (devicesRunning631) or InitiatingProcessFileName has_any (devicesRunning631) ) and ActionType =~ "FileCreated"
```
```KQL
//Internet facing devices with it:
DeviceInfo
| where Timestamp > ago(7d)
| where IsInternetFacing and OSPlatform =~ "Linux"
| extend InternetFacingInfo = AdditionalFields
| extend InternetFacingReason = extractjson("$.InternetFacingReason", InternetFacingInfo, typeof(string)), InternetFacingLocalPort = extractjson("$.InternetFacingLocalPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicPort = extractjson("$.InternetFacingPublicScannedPort", InternetFacingInfo, typeof(int)), InternetFacingScannedPublicIp = extractjson("$.InternetFacingPublicScannedIp", InternetFacingInfo, typeof(string)), InternetFacingLocalIp = extractjson("$.InternetFacingLocalIp", InternetFacingInfo, typeof(string)),InternetFacingTransportProtocol=extractjson("$.InternetFacingTransportProtocol", InternetFacingInfo, typeof(string)), InternetFacingLastSeen = extractjson("$.InternetFacingLastSeen", InternetFacingInfo, typeof(datetime))
| summarize arg_max(Timestamp, *) by DeviceId
| join DeviceNetworkEvents on DeviceId
| where LocalPort == 631
```

## Defender EASM

```KQL
// Detection opportunity 2: NetSupport running from unexpected directory
DeviceProcessEvents
| where ( ProcessVersionInfoCompanyName contains "netsupport" or ProcessVersionInfoProductName contains "netsupport" ProcessVersionInfoCompanyName contains "Crosstec" or ProcessVersionInfoProductName contains "Crosstec") and not ( FolderPath has_any ("Program Files (x86)\\","Program Files\\"))
```
