# Source: Detailed Report https://thedfirreport.com/2023/01/23/sharefinder-how-threat-actors-discover-file-shares/

# SIGMAs:
	-https://github.com/The-DFIR-Report/Sigma-Rules/blob/main/rules/windows/builtin/win_security_invoke_sharefinder_discovery.yml
	- https://github.com/The-DFIR-Report/Sigma-Rules/blob/main/rules/windows/powershell/powershell_script/posh_ps_invoke_sharefinder_discovery.yml
	- https://github.com/The-DFIR-Report/Sigma-Rules/blob/main/rules/network/zeek/zeek_smb_mapping_invoke-sharefinder_discovery.yml

# Encoded data. Adversaries may encode data to make the content of command and control traffic more difficult to detect. 
//T1132 - T1132.001 - Base64 Encoded data. Adversaries may encode data to make the content of command and control traffic more difficult to detect. 
DeviceProcessEvents 
| where FileName =~ "powershell.exe"
//filter out FPs caused by the MDE SenseIR binary
| where InitiatingProcessParentFileName != "SenseIR.exe"
//filter out FPs caused by Nutanix
| where InitiatingProcessFolderPath !contains "c:\\program files\\nutanix"
//filter out noise caused by Windows Defender Exploit Guard
| where InitiatingProcessCommandLine !startswith "gc_worker.exe -a WindowsDefenderExploitGuard"
//filter out noise caused by ansible service account
| where InitiatingProcessAccountName != "svc-ansiblew"
| extend SplitLaunchString = split(ProcessCommandLine, " ")
| mvexpand SplitLaunchString
| where SplitLaunchString matches regex "^[A-Za-z0-9+/]{50,}[=]{0,2}$"
| extend Base64 = tostring(SplitLaunchString)
| extend DecodedString = base64_decodestring(Base64)
| where isnotempty(DecodedString)
| extend test = replace(@'\00', @'', DecodedString)
| extend DShash = hash_md5(DecodedString)
| where DShash != "765213794bd23a89ce9a84459a0cef80"
| where InitiatingProcessCommandLine contains "Invoke-ShareFinder" or DecodedString contains "Invoke-ShareFinder"
