
## check for phishing emails potentially using ipfs to host malicious content used in phishing campaigns.

```
//check for phishing emails potentially using ipfs to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
let domains = externaldata (data:string)[h@"https://raw.githubusercontent.com/volexity/threat-intel/main/2023/2023-06-28%20POWERSTAR/attachments/ipfs.txt"];
EmailEvents
| where TimeGenerated > ago (30d)
| join EmailUrlInfo on NetworkMessageId
| where Url has_any (domains) and DeliveryAction !~ "Blocked"
```


## check for subsequent connections to the site

```
//check for subsequent connections to the site
let domains = externaldata (data:string)
[h@"https://raw.githubusercontent.com/volexity/threat-intel/main/2023/2023-06-28%20POWERSTAR/attachments/ipfs.txt"];
DeviceNetworkEvents
| where TimeGenerated > ago (30d)
| where RemoteUrl has_any (domains)
```
