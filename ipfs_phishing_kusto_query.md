# IPFS (InterPlanetary File System) Phishing Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Detects phishing campaigns that use IPFS (ipfs.io) to host malicious content. Identifies inbound emails with IPFS links and subsequent network connections to IPFS infrastructure.

#### Risk
Adversaries abuse IPFS as a hosting platform for phishing pages and malware payloads. IPFS links are difficult to take down and the decentralized nature complicates blocking.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://blog.talosintelligence.com/ipfs-abuse/
- https://github.com/Cisco-Talos/IOCs/tree/main/2022/11

## Defender For Endpoint
```KQL
//check for phishing emails being delivered that  potentially use interplanetary file system (ipfs) to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
EmailEvents
| where TimeGenerated > ago(14d)
| join EmailUrlInfo on NetworkMessageId
| where EmailDirection =~ "Inbound" and Url contains "ipfs.io"
```

```KQL
//check for phishing emails being delivered that  potentially use interplanetary file system (ipfs) to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
EmailEvents
| where TimeGenerated > ago(14d)
| join EmailUrlInfo on NetworkMessageId
| where EmailDirection =~ "Inbound" and Url contains "ipfs.io" and DeliveryAction != 'Blocked'
```

```KQL
// you may need to adjust your tables and fields accordingly but the intent is to check your URI or request fields using the regex below
CommonSecurityLog | where (cs_uri matches regex @'(?i)ipfs.io/ipfs.+\..+@.+\..+')
```

## Sentinel
```KQL
//check for phishing emails being delivered that  potentially use interplanetary file system (ipfs) to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
EmailEvents
| where TimeGenerated > ago(14d)
| join EmailUrlInfo on NetworkMessageId
| where EmailDirection =~ "Inbound" and Url contains "ipfs.io"
```

```KQL
//check for phishing emails being delivered that  potentially use interplanetary file system (ipfs) to host malicious content used in phishing campaigns.
//check for subsequent connections to the site: DeviceNetworkEvents | where RemoteUrl contains "ipfs.io"
//https://blog.talosintelligence.com/ipfs-abuse/
//https://github.com/Cisco-Talos/IOCs/tree/main/2022/11
EmailEvents
| where TimeGenerated > ago(14d)
| join EmailUrlInfo on NetworkMessageId
| where EmailDirection =~ "Inbound" and Url contains "ipfs.io" and DeliveryAction != 'Blocked'
```

```KQL
// you may need to adjust your tables and fields accordingly but the intent is to check your URI or request fields using the regex below
CommonSecurityLog | where (cs_uri matches regex @'(?i)ipfs.io/ipfs.+\..+@.+\..+')
```
