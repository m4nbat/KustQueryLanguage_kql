# Unusual Discord Network Connection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102 | Web Service | [Web Service](https://attack.mitre.org/techniques/T1102/) |
| T1041 | Exfiltration Over C2 Channel | [Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) |

#### Description
An analytic to detect unusual connections to Discord domains that are known to have been used by malware for command and control or data exfiltration. The queries cover suspicious connections to Discord domains, potential exfiltration via Discord webhooks, and suspicious file downloads from Discord's CDN.

#### Risk
Malware increasingly abuses Discord's infrastructure for command and control, data exfiltration, and payload delivery. Because Discord is a legitimate service widely allowed by corporate firewalls, these connections blend in with normal traffic and are difficult to block without targeted detection.

#### Author <Optional>
- **Name:** Yashraj Solanki, Gavin Knapp
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Discord: I Want to Play a Game](https://www.trellix.com/about/newsroom/stories/research/discord-i-want-to-play-a-game/)

## Defender For Endpoint

### Suspicious Connections to Discord

```KQL

let iocs = datatable (domain:string)['dis.gd','discord.co','discord.com','discord.design','discord.dev','discord.gg','discord.gift','discord.gifts','discord.media','discord.new','discord.store','discord.tools','discord-activities.com','discordactivities.com','discordapp.com','discordapp.net','discordmerch.com','discordpartygames.com','discordsays.com','discordstatus.com','discordapp.io','discordcdn.com'];
let excludedProcessFileNames = datatable (filepattern:string)["Discord Helper","Discord"]; // you will likely need to exclude legitimate browsers or apps
 DeviceNetworkEvents
    | where RemoteUrl has_any (iocs)
    | where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and InitiatingProcessVersionInfoCompanyName != "Discord Inc."
    | extend joinkey = strcat(InitiatingProcessFileName, DeviceName, InitiatingProcessAccountName)
    | join kind=leftouter (DeviceProcessEvents | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize ProcessesRanByParent = make_list(InitiatingProcessCommandLine) by joinkey) on joinkey
    | join kind=leftouter (DeviceFileEvents | where ActionType == "FileCreated" | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize FilesCreated = make_set(FileName) by joinkey) on joinkey
    | project TimeGenerated,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FilesCreated, ProcessesRanByParent, LocalIP, RemoteIP, RemoteUrl, InitiatingProcessAccountUpn

```

### Potential Exfiltration to Discord WebHook

```KQL

let iocs = datatable (domain:string)["discord.com/api/webhooks"];
let excludedProcessFileNames = datatable (filepattern:string)["Discord Helper","Discord"]; // you will likely need to exclude legitimate browsers or apps
 DeviceNetworkEvents
    | where RemoteUrl has_any (iocs)
    | where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and InitiatingProcessVersionInfoCompanyName != "Discord Inc."
    | extend joinkey = strcat(InitiatingProcessFileName, DeviceName, InitiatingProcessAccountName)
    | join kind=leftouter (DeviceProcessEvents | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize ProcessesRanByParent = make_list(InitiatingProcessCommandLine) by joinkey) on joinkey
    | join kind=leftouter (DeviceFileEvents | where ActionType == "FileCreated" | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize FilesCreated = make_set(FileName) by joinkey) on joinkey
    | project TimeGenerated,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FilesCreated, ProcessesRanByParent, LocalIP, RemoteIP, RemoteUrl, InitiatingProcessAccountUpn

```

### Suspicious download from Discord

```KQL

let iocs = datatable (domain:string)["cdn.discordapp.com/attachments"];
let excludedProcessFileNames = datatable (filepattern:string)["Discord Helper","Discord"]; // you will likely need to exclude legitimate browsers or apps
 DeviceNetworkEvents
    | where RemoteUrl has_any (iocs)
    | where not(InitiatingProcessFileName has_any (excludedProcessFileNames)) and InitiatingProcessVersionInfoCompanyName != "Discord Inc."
    | extend joinkey = strcat(InitiatingProcessFileName, DeviceName, InitiatingProcessAccountName)
    | join kind=leftouter (DeviceProcessEvents | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize ProcessesRanByParent = make_list(InitiatingProcessCommandLine) by joinkey) on joinkey
    | join kind=leftouter (DeviceFileEvents | where ActionType == "FileCreated" | extend  joinkey = strcat(InitiatingProcessParentFileName, DeviceName, InitiatingProcessAccountName) | summarize FilesCreated = make_set(FileName) by joinkey) on joinkey
    | project TimeGenerated,  DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FilesCreated, ProcessesRanByParent, LocalIP, RemoteIP, RemoteUrl, InitiatingProcessAccountUpn

```
