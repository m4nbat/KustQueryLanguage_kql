# Ingress Tool Transfer
After gaining a foothold in a victim environment, adversaries often deploy non-native tools for lateral movement and other post-exploitation activity.

## Source: https://redcanary.com/threat-detection-report/techniques/ingress-tool-transfer/

## Suspicious PowerShell commands
Adversaries leverage PowerShell for ingress tool transfer more than any other tool. As such, monitoring for PowerShell process execution in conjunction with suspicious PowerShell commands in the command line can be a fruitful way to detect malicious ingress tool transfers.

process == powershell.exe && command_includes ('downloadstring' || 'downloadata' || 'downloadfile' || 'iex' || '.invoke' || 'invoke-expression')

`DeviceProcessEvents
| where FileName =~ "powershell.exe" and ProcessCommandLine has_any ('downloadstring','downloadata','downloadfile','iex','.invoke','invoke-expression')`


## CertUtil downloading malicious binaries
Adversaries often bypass security controls by using the Windows Certificate Utility (certutil.exe) to download malicious code. In general, they leverage certutil.exe along with the -split command-line option.

process == certutil.exe && command_includes ('urlcache' && 'split')

`DeviceProcessEvents
| where FileName =~ "certutil.exe" and ProcessCommandLine has_any ('urlcache','split')`

## BITSAdmin downloading malicious binaries
It’s not unusual for adversaries, including ones who peddle ransomware, to use BITSAdmin to download arbitrary files from the internet in an effort to evade application blocklisting. The following analytic will look for the execution of bitsadmin.exe with command options that suggest a file is being downloaded:
 
process== bitsadmin.exe && command_includes (download' || 'transfer')

`DeviceProcessEvents
| where FileName =~ "bitsadmin.exe" and ProcessCommandLine has_any ('download','transfer')`








