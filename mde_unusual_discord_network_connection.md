# Title
Unusual Discord Network Connection

# Description
An analytic to detect unusual connections to Discord domains that are known to have been used by malware for command and control or data exfiltration

# Source
https://www.trellix.com/about/newsroom/stories/research/discord-i-want-to-play-a-game/

# Author
- Yashraj Solanki
- Gavin Knapp

# Mitre Techniques

# Query

## Suspicious Connections to Discord

```

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

## Potential Exfiltration to Discord WebHook

```

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

## Suspicious download from Discord

```

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
