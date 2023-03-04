# Queries from the blog: https://redcanary.com/blog/intelligence-insights-november-2022/

# Processes making outbound network connections to Telegram shortened domains t[.]me or tttttt[.]me
`//Detection opportunity: Unexpected processes making outbound network connections to Telegram shortened domains t[.]me or tttttt[.]me
//The following detection analytic identifies unexpected processes making outbound network connections to the Telegram shortened domains  t[.]me or tttttt[.]me. Telegram has been used for command and control (C2) by various stealers including RedLine, Vidar, and Raccoon. Since legitimate applications like Windows browsers, Zscaler, and others have been observed using t[.]me, additional investigation of the executing binary’s reputation is key.
//source: https://redcanary.com/blog/intelligence-insights-november-2022/
let exclusions = datatable(filename:string)["broswer1.exe","browser2.exe","telegram.exe"];
DeviceNetworkEvents
| where not(InitiatingProcessFileName has_any (exclusions)) and (RemoteUrl endswith "t.me" or RemoteUrl endswith "tttttt.me")`
