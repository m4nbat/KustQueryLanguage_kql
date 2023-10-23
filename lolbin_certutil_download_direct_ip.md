# Title
Certutil downloading a file with suspicious command line arguments

# Description
Detects the execution of certutil with certain flags that allow the utility to download files from direct IPs.

# Source
Nasreddine Bencherchali (Nextron Systems)
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
    - https://forensicitguy.github.io/agenttesla-vba-certutil-download/
    - https://news.sophos.com/en-us/2021/04/13/compromised-exchange-server-hosting-cryptojacker-targeting-other-exchange-servers/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
    - https://twitter.com/_JohnHammond/status/1708910264261980634

# MITRE ATT&CK Techniques
  - T1027

# Query

```
//proc_creation_win_certutil_download_direct_ip
DeviceProcessEvents 
| where (FolderPath endswith @'\certutil.exe' or ProcessVersionInfoOriginalFileName =~ @'CertUtil.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'CertUtil.exe') and ProcessCommandLine has_any (@'urlcache ',@'verifyctl ') and ProcessCommandLine has_any (@'://1',@'://2',@'://3',@'://4',@'://5',@'://6',@'://7',@'://8',@'://9') and not ( ProcessCommandLine contains @'://7-')

//proc_creation_win_certutil_download_direct_ip
DeviceNetworkEvents
| where ( InitiatingProcessFileName =~ "certutil.exe" or InitiatingProcessVersionInfoOriginalFileName
 =~ "certutil.exe") and RemoteIPType =~ "Public" and InitiatingProcessCommandLine has_any (@'urlcache ',@'verifyctl ')
```
