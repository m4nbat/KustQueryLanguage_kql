# Rundll32

Like other prevalent ATT&CK techniques, Rundll32 is a native Windows process and a functionally necessary component of the Windows operating system that can’t be blocked or disabled without breaking things. Adversaries typically abuse Rundll32 because it makes it hard to differentiate malicious activity from normal operations. More often than not, we observe adversaries leveraging Rundll32 as a means of credential theft and execution bypass.

From a practical standpoint, Rundll32 enables the execution of dynamic link libraries (DLL). Executing malicious code as a DLL is relatively inconspicuous compared to the more common option of executing malicious code as an executable. Under certain conditions, particularly if you lack controls for blocking DLL loads, the execution of malicious code through Rundll32 can bypass application control solutions.

## Source

## Application bypass with DllRegisterServer function
DLLs that are designed to be loaded by Regsvr32 are expected to have a DllRegisterServer export function implemented. Adversaries will often supply the same DLL to rundll32.exe as well. Executing the DllRegisterServer export function with rundll32.exe is tradecraft that’s unique to adversary behavior and is rarely seen in legitimate scenarios. We’ve observed this behavior in threats including Qbot, Ursnif, and Zloader, to name a few examples.

**Pseudocode:** process == rundll32.exe && command_includes ('DllRegisterServer') 

**kusto**

`DeviceProcessEvents
| where FileName =~ "rundll32.exe" and ProcessCommandLine contains "DllRegisterServer"`

## Rundll32 with suspicious process lineage

As is the case with most techniques in this report, it’s critical that you are able to take stock of what is normal in your environment if you hope to be able to identify what isn’t. In the context of Rundll32, you’ll want to monitor for executions of rundll32.exe from unusual parent processes

**Pseudocode:** parent_process == ('winword.exe' || 'excel.exe' || 'msaccess.exe' || 'lsass.exe' || 'taskeng.exe' || 'winlogon.exe' || 'schtask.exe' || 'regsvr32.exe' || 'wmiprvse.exe' || 'wsmprovhost.exe') && process == rundll32.exe 

**kusto**

`DeviceProcessEvents
| where InitiatingProcessFileName in~ ('winword.exe','excel.exe','msaccess.exe','lsass.exe','taskeng.exe','winlogon.exe','schtask.exe','regsvr32.exe','wmiprvse.exe','wsmprovhost.exe') and FileName =~ "rundll32.exe"`

## Suspicious export functionalities

Consider monitoring for instances of rundll32.exe running Windows native DLLs that have export functionalities that adversaries commonly leverage for executing malicious code and evading defensive controls.

**Pseudocode:** process == rundll32.exe || modload == comsvcs.dll && command_includes ('MiniDump' || '#24')

**kusto**

`let processEvents = DeviceProcessEvents
| where FileName == "rundll32.exe" and ProcessCommandLine has_any ("MiniDump","#24");
let moduleEvents = DeviceImageLoadEvents
| where FileName =~ "comsvcs.dll" and InitiatingProcessCommandLine has_any ("MiniDump","#24");
union isfuzzy=true processEvents,moduleEvents`


## Rundll injection into LSASS

The following pseudo-detector should help security teams detect instances where Rundll32 opens a cross process handle into LSASS to collect credentials.Rundll32 does not normally execute without corresponding command-line arguments and while spawning a child process. Given this, you may want to alert on the execution of processes that appear to be rundll32.exe without any command-line arguments , especially when they spawn child processes or make network connections.

**Pseudocode:** process_name == rundll32.exe &&  cross_process == lsass.exe

**kusto**

`DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "rundll32.exe" //and InitiatingProcessFileName =~ "lsass.exe"`

`DeviceProcessEvents
| where InitiatingProcessFileName =~ "rundll32.exe" and isempty(InitiatingProcessCommandLine)`


## Rundll32 without a command line

Rundll32 does not normally execute without corresponding command-line arguments and while spawning a child process. Given this, you may want to alert on the execution of processes that appear to be rundll32.exe without any command-line arguments , especially when they spawn child processes or make network connections.

**Pseudocode:** process == rundll32.exe && command_includes (“”)* && has_network_connection || has_child_process

**kusto**

`DeviceProcessEvents
| where FileName in ('rundll32.exe')
//regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command.
| where ProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$"
//regex to extract the commandline after the .exe
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, ProcessCommandLine)
| where isempty(CommandLineArgs)`


`DeviceNetworkEvents
| where InitiatingProcessFileName =~ "rundll32.exe"
//regex to extract the commandline following a windows binary as MDE commandline field usually contains "123.exe" or '123.exe' or 123.exe followed by a command.
| where ProcessCommandLine matches regex "(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$"
//regex to extract the commandline after the .exe
| extend CommandLineArgs = extract("(['\"]?\\w+\\.exe['\"]?)(\\s+.+)?$", 2, ProcessCommandLine)
| where isempty(CommandLineArgs)`

