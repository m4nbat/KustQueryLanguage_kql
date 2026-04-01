# Certutil downloading a file with suspicious command line arguments

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1027 | Obfuscated Files or Information | [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |

#### Description
Detects the execution of certutil with certain flags that allow the utility to download files from direct IPs.

#### Risk
Certutil downloading files directly from IP addresses (bypassing domain-based web filtering) is a strong indicator of malicious activity, often used by attackers for tool staging or payload delivery.

#### Author <Optional>
- **Name:** Nasreddine Bencherchali (Nextron Systems)
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Microsoft Certutil documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [AgentTesla VBA Certutil Download](https://forensicitguy.github.io/agenttesla-vba-certutil-download/)
- [Compromised Exchange Server hosting cryptojacker](https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/)
- [egre55 Twitter](https://twitter.com/egre55/status/1087685529016193025)
- [LOLBAS Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [JohnHammond Twitter](https://twitter.com/_JohnHammond/status/1708910264261980634)

## Defender For Endpoint

```KQL
//proc_creation_win_certutil_download_direct_ip
DeviceProcessEvents 
| where (FolderPath endswith @'\certutil.exe' or ProcessVersionInfoOriginalFileName =~ @'CertUtil.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'CertUtil.exe') and ProcessCommandLine has_any (@'urlcache ',@'verifyctl ') and ProcessCommandLine has_any (@'://1',@'://2',@'://3',@'://4',@'://5',@'://6',@'://7',@'://8',@'://9') and not ( ProcessCommandLine contains @'://7-')
```

```KQL
//proc_creation_win_certutil_download_direct_ip
DeviceNetworkEvents
| where ( InitiatingProcessFileName =~ "certutil.exe" or InitiatingProcessVersionInfoOriginalFileName
 =~ "certutil.exe") and RemoteIPType =~ "Public" and InitiatingProcessCommandLine has_any (@'urlcache ',@'verifyctl ')
```
