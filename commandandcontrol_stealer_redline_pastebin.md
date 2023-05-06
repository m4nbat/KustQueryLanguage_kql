# Redline stealer using pastebin

Redline Stealer reported to be using pastebin to grab C2 configuration.

# Source:

https://twitter.com/NexusFuzzy/status/1654056343127425026?s=19

# Hunt queries

```
let excludedPaths = datatable(path:string)["browserpath1","browserpath2","etc..."];
DeviceNetworkEvents 
| where RemoteUrl contains "pastebin.com" and InitiatingProcessFolderPath !has_any (excludedPaths)
```



