
## check for phishing emails potentially using ipfs to host malicious content used in phishing campaigns.

`//check for phishing emails potentially using ipfs to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
EmailEvents
| join EmailUrlInfo on NetworkMessageId
| where Url contains "ipfs.io" and DeliveryAction != 'Blocked'![image](https://user-images.githubusercontent.com/16122365/222919361-24dadd10-c42e-439c-9552-925a31733f46.png)`


## check for subsequent connections to the site
//check for subsequent connections to the site
DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
