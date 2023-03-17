# AWS Hunt Queries

## EC2 Security Group Backdoor

**SIGMA**

`title: 'Detects Backdooring EC2 Security Groups'
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
level: 'high'`

# Sentinel

`AWSCloudTrail 
| where ((eventName =~ @'AuthorizeSecurityGroupIngress' and eventSource =~ @'ec2.amazonaws.com') and not (sourceIPAddress in~ (@'107.14.3.11', @'107.14.3.10', @'107.14.3.12')))`
