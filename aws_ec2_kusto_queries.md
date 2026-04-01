# AWS EC2 Security Group Backdoor Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | [Impair Defenses: Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/) |

#### Description
Detects attempts to backdoor AWS EC2 Security Groups by inserting unauthorized inbound access rules. Adversaries may modify security group ingress rules to allow access from attacker-controlled IP addresses, creating a persistent backdoor into EC2 instances.

#### Risk
Unauthorized modification of EC2 security group ingress rules could allow attacker-controlled IP addresses to access EC2 instances, bypassing network-level security controls and enabling persistent remote access.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- https://attack.mitre.org/techniques/T1562/007/

## SIGMA Rule

```
title: 'Detects Backdooring EC2 Security Groups'
description: 'Detects the insertion of backdoor access into EC2'
author: 'Gavin Knapp'
status: experimental
logsource:
    service: cloudtrail
detection:
  event_source:
  - eventName: AuthorizeSecurityGroupIngress
  - eventSource: ec2.amazonaws.com
  Filter_Trusted_Ips:
   sourceIPAddress:
     - 1.1.1.2
     - 8.8.8.8
  condition: "all of event_source and not Filter_Trusted_Ips"
fields:
    - 'sourceIPAddress'
    - 'requestParameters.cidrIp'
    - 'userIdentity.arn'
falsepositives:
    - 'Valid changes to security groups'
level: 'high'
```

## Sentinel
```KQL
AWSCloudTrail 
| where ((eventName =~ @'AuthorizeSecurityGroupIngress' and eventSource =~ @'ec2.amazonaws.com') and not (sourceIPAddress in~ (@'107.14.3.11', @'107.14.3.10', @'107.14.3.12')))
```
