# Rundll32

Like other prevalent ATT&CK techniques, Rundll32 is a native Windows process and a functionally necessary component of the Windows operating system that can’t be blocked or disabled without breaking things. Adversaries typically abuse Rundll32 because it makes it hard to differentiate malicious activity from normal operations. More often than not, we observe adversaries leveraging Rundll32 as a means of credential theft and execution bypass.

From a practical standpoint, Rundll32 enables the execution of dynamic link libraries (DLL). Executing malicious code as a DLL is relatively inconspicuous compared to the more common option of executing malicious code as an executable. Under certain conditions, particularly if you lack controls for blocking DLL loads, the execution of malicious code through Rundll32 can bypass application control solutions.

## Source

## Application bypass with DllRegisterServer function
DLLs that are designed to be loaded by Regsvr32 are expected to have a DllRegisterServer export function implemented. Adversaries will often supply the same DLL to rundll32.exe as well. Executing the DllRegisterServer export function with rundll32.exe is tradecraft that’s unique to adversary behavior and is rarely seen in legitimate scenarios. We’ve observed this behavior in threats including Qbot, Ursnif, and Zloader, to name a few examples.


## Rundll32 with suspicious process lineage

As is the case with most techniques in this report, it’s critical that you are able to take stock of what is normal in your environment if you hope to be able to identify what isn’t. In the context of Rundll32, you’ll want to monitor for executions of rundll32.exe from unusual parent processes



## Suspicious export functionalities

Consider monitoring for instances of rundll32.exe running Windows native DLLs that have export functionalities that adversaries commonly leverage for executing malicious code and evading defensive controls.


## Rundll injection into LSASS

The following pseudo-detector should help security teams detect instances where Rundll32 opens a cross process handle into LSASS to collect credentials.Rundll32 does not normally execute without corresponding command-line arguments and while spawning a child process. Given this, you may want to alert on the execution of processes that appear to be rundll32.exe without any command-line arguments , especially when they spawn child processes or make network connections.


## Rundll32 without a command line

Rundll32 does not normally execute without corresponding command-line arguments and while spawning a child process. Given this, you may want to alert on the execution of processes that appear to be rundll32.exe without any command-line arguments , especially when they spawn child processes or make network connections.

