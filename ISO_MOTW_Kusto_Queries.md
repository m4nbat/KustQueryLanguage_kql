# ISO File and MOTW related attack behaviours

`//ISO or Image Mount Indicator in Recent Files
//https://github.com/SigmaHQ/sigma/blob/d459483ef6bb889fb8da1baa17a713a4f1aa8897/rules/windows/file_event/file_event_win_iso_file_recent.yml
//https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
//https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
//https://blog.emsisoft.com/en/32373/beware-new-wave-of-malware-spreads-via-iso-file-email-attachments/
//https://insights.sei.cmu.edu/blog/the-dangers-of-vhd-and-vhdx-files/
//Detects the creation of recent element file that points to an .ISO, .IMG, .VHD or .VHDX file as often used in phishing attacks. This can be a false positive on server systems but on workstations users should rarely mount .iso or .img files.
DeviceFileEvents 
| where ((FolderPath endswith @'.iso.lnk' or FolderPath endswith @'.img.lnk' or FolderPath endswith @'.vhd.lnk' or FolderPath endswith @'.vhdx.lnk') and (FolderPath contains @'\Microsoft\Windows\Recent\'))`

`//Suspicious VHD, VHDX, or ISO Image Download From Browser
//Malware can use mountable Virtual Hard Disk .vhd, .vhdx, .iso file to encapsulate payloads and evade security controls
//Legitimate user creation potentially someone working with virtualisation software, IT services or training related
//confirm hash of original file and validate source e.g. the site it was downloaded from.
//https://github.com/SigmaHQ/sigma/blob/d459483ef6bb889fb8da1baa17a713a4f1aa8897/rules/windows/file_event/file_event_win_iso_file_recent.yml
//https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/
//https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
//https://blog.emsisoft.com/en/32373/beware-new-wave-of-malware-spreads-via-iso-file-email-attachments/
//https://insights.sei.cmu.edu/blog/the-dangers-of-vhd-and-vhdx-files
DeviceFileEvents | where ((InitiatingProcessFolderPath endswith @'chrome.exe' or InitiatingProcessFolderPath endswith @'firefox.exe' or InitiatingProcessFolderPath endswith @'microsoftedge.exe' or InitiatingProcessFolderPath endswith @'microsoftedgecp.exe' or InitiatingProcessFolderPath endswith @'msedge.exe' or InitiatingProcessFolderPath endswith @'iexplorer.exe' or InitiatingProcessFolderPath endswith @'brave.exe' or InitiatingProcessFolderPath endswith @'opera.exe') and FolderPath has_any ('.vhd','.iso','.vhdx'))`

`//ISO Image Mount: Detects the mount of ISO images on an endpoint
//https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
//https://www.proofpoint.com/us/blog/threat-insight/threat-actor-profile-ta2719-uses-colorful-lures-deliver-rats-local-languages
//https://twitter.com/MsftSecIntel/status/1257324139515269121
//https://github.com/SigmaHQ/sigma/blob/04f72b9e78f196544f8f1331b4d9158df34d7ecf/rules/windows/builtin/security/win_iso_mount.yml
SecurityEvent 
| where ((EventID == 4663 and ObjectServer =~ @'Security' and ObjectType =~ @'File' and ObjectName contains @'\Device\CdRom') and (ObjectName !~ @'\Device\CdRom0\setup.exe'))`
