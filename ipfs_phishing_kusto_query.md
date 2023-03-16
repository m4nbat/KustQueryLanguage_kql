# IPFS Web3 Phish

# All emails

`//check for phishing emails being delivered that  potentially use interplanetary file system (ipfs) to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
EmailEvents
| where TimeGenerated > ago(14d)
| join EmailUrlInfo on NetworkMessageId
| where EmailDirection =~ "Inbound" and Url contains "ipfs.io"`

# Delivered emails

`//check for phishing emails being delivered that  potentially use interplanetary file system (ipfs) to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
EmailEvents
| where TimeGenerated > ago(14d)
| join EmailUrlInfo on NetworkMessageId
| where EmailDirection =~ "Inbound" and Url contains "ipfs.io" and DeliveryAction != 'Blocked'`

# Looking for post phish clickers
// you may need to adjust your tables and fields accordingly but the intent is to check your URI or request fields using the regex below
CommonSecurityLog | where (cs_uri matches regex @'(?i)ipfs.io/ipfs.+\..+@.+\..+')
