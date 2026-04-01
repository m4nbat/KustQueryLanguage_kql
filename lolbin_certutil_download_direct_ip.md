# Certutil Downloading Files from Direct IP Addresses

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1105 | Ingress Tool Transfer | [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| T1027 | Obfuscated Files or Information | [Obfuscated Files](https://attack.mitre.org/techniques/T1027/) |

#### Description
Detects certutil.exe being used to download files from direct IP addresses using urlcache or verifyctl flags. This is a common living-off-the-land technique to bypass web filtering.

#### Risk
Certutil is a legitimate Windows tool frequently abused to download malicious payloads from direct IP addresses, bypassing domain-based URL filtering. This technique was used by multiple threat actors including in Exchange server exploitation.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://lolbas-project.github.io/lolbas/Binaries/Certutil/
- https://twitter.com/egre55/status/1087685529016193025

## Defender For Endpoint
```KQL
//proc_creation_win_certutil_download_direct_ip
DeviceProcessEvents 
| where (FolderPath endswith @'\certutil.exe' or ProcessVersionInfoOriginalFileName =~ @'CertUtil.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'CertUtil.exe') and ProcessCommandLine has_any (@'urlcache ',@'verifyctl ') and ProcessCommandLine has_any (@'://1',@'://2',@'://3',@'://4',@'://5',@'://6',@'://7',@'://8',@'://9') and not ( ProcessCommandLine contains @'://7-')

//proc_creation_win_certutil_download_direct_ip
DeviceNetworkEvents
| where ( InitiatingProcessFileName =~ "certutil.exe" or InitiatingProcessVersionInfoOriginalFileName
 =~ "certutil.exe") and RemoteIPType =~ "Public" and InitiatingProcessCommandLine has_any (@'urlcache ',@'verifyctl ')
```

## Sentinel
```KQL
//proc_creation_win_certutil_download_direct_ip
DeviceProcessEvents 
| where (FolderPath endswith @'\certutil.exe' or ProcessVersionInfoOriginalFileName =~ @'CertUtil.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'CertUtil.exe') and ProcessCommandLine has_any (@'urlcache ',@'verifyctl ') and ProcessCommandLine has_any (@'://1',@'://2',@'://3',@'://4',@'://5',@'://6',@'://7',@'://8',@'://9') and not ( ProcessCommandLine contains @'://7-')

//proc_creation_win_certutil_download_direct_ip
DeviceNetworkEvents
| where ( InitiatingProcessFileName =~ "certutil.exe" or InitiatingProcessVersionInfoOriginalFileName
 =~ "certutil.exe") and RemoteIPType =~ "Public" and InitiatingProcessCommandLine has_any (@'urlcache ',@'verifyctl ')
```
