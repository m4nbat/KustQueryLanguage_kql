# Exfiltration to Known Scattered Spider Domains Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                           | Link                                         |
|--------------|---------------------------------|----------------------------------------------|
| T1567.002       | Exfiltration to Cloud Storage    | [Exfiltration to Cloud Storage ](https://attack.mitre.org/techniques/T1567/002/) |

#### Description
This detection rule aims to identify data exfiltration attempts to domains known to be associated with the Scattered Spider threat group. The query searches for network events where devices connect to a list of predefined domains, such as "transfer.sh", "Mega.nz", and "riseup.net", which are commonly used by Scattered Spider for data exfiltration.

#### Risk
The primary risk addressed by this rule is the unauthorized transmission of sensitive data to external servers controlled by attackers. Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet. Exfiltration to these specific domains can signify an active compromise or data breach attempt.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [CISA Advisory on Data Exfiltration Techniques](https://www.cisa.gov/uscert/ncas/alerts)
- [Microsoft Security Blog on Cyber Threats](https://www.microsoft.com/en-us/security/blog/)

## Defender For Endpoint
```KQL
// Exfiltration to known Scattered Spider Domains
let exfilDomains = dynamic(["transfer.sh", "Mega.nz", "riseup.net"]);  
DeviceNetworkEvents 
| where RemoteUrl in exfilDomains 
| summarize count() by DeviceName, Timestamp
```

## Sentinel 
```KQL
// Exfiltration to known Scattered Spider Domains
let exfilDomains = dynamic(["transfer.sh", "Mega.nz", "riseup.net"]);  
DeviceNetworkEvents 
| where RemoteUrl in exfilDomains 
| summarize count() by DeviceName, TimeGenerated  

```
