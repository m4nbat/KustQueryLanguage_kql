# Reddit used for C2

# SIGMA rule:
https://github.com/m4nbat/sigma/blob/master/rules/windows/network_connection/net_connection_win_reddit_api_non_browser_access.yml

# Kusto
`//Processes interacting with Reddit API (Has been known to be used for C2 communication)
// https://github.com/kleiton0x00/RedditC2
//false positives - browsers going to the URL. Or a legitimate application that uses Reddit API
let browserNames = datatable (browser:string)["msedge.exe","chrome.exe","iexplorer.exe","brave.exe","firefox.exe"]; //add more broswers where needed for exclusion
DeviceNetworkEvents
| where not(InitiatingProcessFileName has_any (browserNames)) and RemoteUrl contains "reddit.com/api/"`
