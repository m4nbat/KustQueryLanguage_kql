# Polyfill Supply Chain Attack Detection

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1071.001 | Application Layer Protocol: Web Protocols | [Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |

#### Description
This detection rule identifies network events related to the recent Polyfill supply chain attack where malicious domains such as `googie-anaiytics.com` and `kuurza.com` were used to exfiltrate data.

#### Risk
This detection rule addresses the risk of data exfiltration and potential compromise from the Polyfill supply chain attack. The malicious domains involved are indicators of compromise (IOCs) used to identify infected systems attempting to communicate with the attacker's infrastructure.

#### Author
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [Sansec Research on Polyfill Supply Chain Attack](https://sansec.io/research/polyfill-supply-chain-attack)
- https://kqlquery.com/
- https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules

## Defender For Endpoint

```KQL
// Query to detect HTTP connections to malicious domains
DeviceNetworkEvents 
| where ActionType == @"HttpConnectionInspected"
| extend ConnectInfo = todynamic(AdditionalFields)
| extend HttpHost = ConnectInfo.host
| where HttpHost contains "googie-anaiytics.com" or HttpHost contains "kuurza.com"
```

```KQL
// Query to detect DNS responses for malicious domains
DeviceNetworkEvents
| where ActionType == "DnsQueryResponse"
| extend QueryInfo = todynamic(AdditionalFields)
| extend DnsQuery = QueryInfo.query
| where DnsQuery contains "googie-anaiytics.com" or DnsQuery contains "kuurza.com"
```
