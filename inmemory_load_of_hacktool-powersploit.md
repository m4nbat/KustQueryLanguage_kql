## MDE and Sentinel

```
//PowerSploit in memory module loads
let iocList = dynamic ([
"powersploit",
"Win32",
"DynamicAssembly", //can cause FPs
"ReflectedDelegate",
"SSPI",
"SSPI2",
"VaultUtil",
"VSSUtil",
"BlueScreen",
"Win32"
]);
DeviceEvents
| extend module = parse_json(AdditionalFields).ModuleILPathOrName
| where ActionType =~ "ClrUnbackedModuleLoaded" and module in~ (iocList) and InitiatingProcessFileName =~ "powershell.exe"
```
