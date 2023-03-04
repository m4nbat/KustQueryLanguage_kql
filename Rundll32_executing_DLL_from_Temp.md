# Rundll32 executing DLL files located in the Windows Temp directory
The following pseudo-detection analytic identifies instances of the Windows Rundll32 process loading code from DLL files located in the Windows Temp directory. It’s possible that some enterprise software in your environment will execute DLLs from windows\temp, so additional investigation may be needed to determine if the behavior is malicious.

`//Rundll32 executing DLL files located in the Windows Temp directory
//The following detection analytic identifies instances of the Windows Rundll32 process loading code from DLL files located in the Windows Temp directory. It’s possible that some enterprise software in your environment will execute DLLs from windows\temp, so additional investigation may be needed to determine if the behavior is malicious.
let trustedDlls = datatable(dll:string)["trustedDll.dll"]; //place trusted DLLs that launch from temp folders here.
DeviceProcessEvents
| where (InitiatingProcessFileName =~ "rundll32.exe" and ProcessCommandLine contains @"windows\temp") and not(ProcessCommandLine has_any (trustedDlls))`
