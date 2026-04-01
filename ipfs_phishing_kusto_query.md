# IPFS Web3 Phish

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | [Phishing](https://attack.mitre.org/techniques/T1566/) |
| T1566.002 | Spearphishing Link | [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) |

#### Description
Queries to detect phishing emails using the Interplanetary File System (IPFS) to host malicious content. IPFS is increasingly abused by threat actors to host phishing pages as the decentralised nature makes takedowns more difficult.

#### Risk
Detection of IPFS-hosted phishing content in inbound emails indicates an active phishing campaign leveraging decentralised infrastructure, making remediation more challenging than traditional web-hosted phishing.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Cisco Talos - IPFS Abuse](https://blog.talosintelligence.com/ipfs-abuse/)
- [Cisco Talos IOCs](https://github.com/Cisco-Talos/IOCs/tree/main/2022/11)

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
