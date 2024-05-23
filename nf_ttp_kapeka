//Example QUEUESEED for the batch file
//TTP QUEUESEED malware behaviour
//UA CERT Article
//https://medium.com/detect-fyi/uac-0133-sandworm-plans-for-cyber-sabotage-at-almost-20-critical-infrastructure-facilities-in-d923a6cbcef4
//https://cert.gov.ua/article/6278706
DeviceProcessEvents
| where ( ProcessCommandLine has_all ("%COMSPEC%",@"/c",@"%APPDATA%\",".bat") or InitiatingProcessCommandLine has_all ("%COMSPEC%",@"/c",@"%APPDATA%\",".bat") )

//Example KAPEKA for the batch file
//TTP KAPEKA malware behaviour
//UA CERT Article
//https://medium.com/detect-fyi/uac-0133-sandworm-plans-for-cyber-sabotage-at-almost-20-critical-infrastructure-facilities-in-d923a6cbcef4
//https://cert.gov.ua/article/6278706
DeviceProcessEvents
| where ( ProcessCommandLine has_all (@"C:\Windows\system32\cmd.exe",@"/c",@"C:\Users\",@"\AppData\",".bat") or ProcessCommandLine has_all (@"C:\Windows\system32\cmd.exe",@"/c",@"C:\Users\",@"\AppData\",".bat") )

//Additional registry entries for the backdoor for SENS API (KAPEKA)
//Scheduled Task Persistence Mechanisms
//https://medium.com/detect-fyi/uac-0133-sandworm-plans-for-cyber-sabotage-at-almost-20-critical-infrastructure-facilities-in-d923a6cbcef4
//https://cert.gov.ua/article/6278706
DeviceProcessEvents
| where ProcessCommandLine has_all ("/c","schtasks","/create","/sc","ONSTART","/tn","Sens Api","/f","/np","/tr",".wll")

//Additional registry entries for the backdoor for SENS API (KAPEKA)
//Scheduled Task Persistence Mechanisms
//https://medium.com/detect-fyi/uac-0133-sandworm-plans-for-cyber-sabotage-at-almost-20-critical-infrastructure-facilities-in-d923a6cbcef4
//https://cert.gov.ua/article/6278706
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet" and RegistryKey endswith @"\Windows\CurrentVersion\Run" and RegistryValueName =~ "Sens Api" and RegistryValueData has_all (@"rundll32.exe",@".wll",@"#1") 
