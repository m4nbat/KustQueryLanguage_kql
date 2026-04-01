# AWS EC2 Security Group Backdoor Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | [Account Manipulation](https://attack.mitre.org/techniques/T1098/) |

#### Description
Detects the insertion of backdoor access into AWS EC2 security groups by identifying AuthorizeSecurityGroupIngress API calls from untrusted IP addresses.

#### Risk
Adversaries compromise AWS environments and modify EC2 security groups to open unauthorized inbound access, enabling persistent remote access or exfiltration channels.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://aws.amazon.com/cloudtrail/

## Defender For Endpoint
```KQL
AWSCloudTrail 
| where ((eventName =~ @'AuthorizeSecurityGroupIngress' and eventSource =~ @'ec2.amazonaws.com') and not (sourceIPAddress in~ (@'107.14.3.11', @'107.14.3.10', @'107.14.3.12')))
```

## Sentinel
```KQL
AWSCloudTrail 
| where ((eventName =~ @'AuthorizeSecurityGroupIngress' and eventSource =~ @'ec2.amazonaws.com') and not (sourceIPAddress in~ (@'107.14.3.11', @'107.14.3.10', @'107.14.3.12')))
```
