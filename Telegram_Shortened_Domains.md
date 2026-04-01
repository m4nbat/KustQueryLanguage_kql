# Unexpected Process Connections to Telegram Shortened Domains (C2 Detection)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1102.001 | Web Service: Dead Drop Resolver | [Dead Drop Resolver](https://attack.mitre.org/techniques/T1102/001/) |

#### Description
Detects unexpected non-browser processes making outbound network connections to Telegram shortened domains (t.me or tttttt.me), which have been used for C2 communication by stealers.

#### Risk
Multiple stealer malware families use Telegram as a C2 channel. RedLine, Vidar, and Raccoon have all been observed using t.me short URLs for command and control.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://redcanary.com/blog/intelligence-insights-november-2022/

## Defender For Endpoint
```KQL
//Detection opportunity: Unexpected processes making outbound network connections to Telegram shortened domains t[.]me or tttttt[.]me
//The following detection analytic identifies unexpected processes making outbound network connections to the Telegram shortened domains  t[.]me or tttttt[.]me. Telegram has been used for command and control (C2) by various stealers including RedLine, Vidar, and Raccoon. Since legitimate applications like Windows browsers, Zscaler, and others have been observed using t[.]me, additional investigation of the executing binary’s reputation is key.
//source: https://redcanary.com/blog/intelligence-insights-november-2022/
let exclusions = datatable(filename:string)["broswer1.exe","browser2.exe","telegram.exe"];
DeviceNetworkEvents
| where not(InitiatingProcessFileName has_any (exclusions)) and (RemoteUrl endswith "t.me" or RemoteUrl endswith "tttttt.me")
```

## Sentinel
```KQL
//Detection opportunity: Unexpected processes making outbound network connections to Telegram shortened domains t[.]me or tttttt[.]me
//The following detection analytic identifies unexpected processes making outbound network connections to the Telegram shortened domains  t[.]me or tttttt[.]me. Telegram has been used for command and control (C2) by various stealers including RedLine, Vidar, and Raccoon. Since legitimate applications like Windows browsers, Zscaler, and others have been observed using t[.]me, additional investigation of the executing binary’s reputation is key.
//source: https://redcanary.com/blog/intelligence-insights-november-2022/
let exclusions = datatable(filename:string)["broswer1.exe","browser2.exe","telegram.exe"];
DeviceNetworkEvents
| where not(InitiatingProcessFileName has_any (exclusions)) and (RemoteUrl endswith "t.me" or RemoteUrl endswith "tttttt.me")
```
