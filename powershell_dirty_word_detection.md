#

## SOURCE

- https://gist.github.com/nasbench/50cd0b64bedacabccecc9149c15228da#file-pwsh_dirty_words-yml

## MDE 

```
let dirtyWordList = datatable(word:string)["Add-Type"
,"AddSecurityPackage"
,"AdjustTokenPrivileges"
,"AllocHGlobal"
,"BindingFlags"
,"Bypass"
,"CloseHandle"
,"CreateDecryptor"
,"CreateEncryptor"
,"CreateProcessWithToken"
,"CreateRemoteThread"
,"CreateThread"
,"CreateType"
,"CreateUserThread"
,"Cryptography"
,"CryptoServiceProvider"
,"CryptoStream"
,"DangerousGetHandle"
,"DeclaringMethod"
,"DeclaringType"
,"DefineConstructor"
,"DefineDynamicAssembly"
,"DefineDynamicModule"
,"DefineEnum"
,"DefineField"
,"DefineLiteral"
,"DefinePInvokeMethod"
,"DefineType"
,"DeflateStream"
,"DeviceIoControl"
,"DllImport"
,"DuplicateTokenEx"
,"Emit"
,"EncodedCommand"
,"EnumerateSecurityPackages"
,"ExpandString"
,"FreeHGlobal"
,"FreeLibrary"
,"FromBase64String"
,"GetAssemblies"
,"GetAsyncKeyState"
,"GetConstructor"
,"GetConstructors"
,"GetDefaultMembers"
,"GetDelegateForFunctionPointer"
,"GetEvent"
,"GetEvents"
,"GetField"
,"GetFields"
,"GetForegroundWindow"
,"GetInterface"
,"GetInterfaceMap"
,"GetInterfaces"
,"GetKeyboardState"
,"GetLogonSessionData"
,"GetMember"
,"GetMembers"
,"GetMethod"
,"GetMethods"
,"GetModuleHandle"
,"GetNestedType"
,"GetNestedTypes"
,"GetPowerShell"
,"GetProcAddress"
,"GetProcessHandle"
,"GetProperties"
,"GetProperty"
,"GetTokenInformation"
,"GetTypes"
,"ILGenerator"
,"ImpersonateLoggedOnUser"
,"InteropServices"
,"IntPtr"
,"InvokeMember"
,"kernel32"
,"LoadLibrary"
,"LogPipelineExecutionDetails"
,"MakeArrayType"
,"MakeByRefType"
,"MakeGenericType"
,"MakePointerType"
,"Marshal"
,"memcpy"
,"MemoryStream"
,"Methods"
,"MiniDumpWriteDump"
,"NonPublic"
,"OpenDesktop"
,"OpenProcess"
,"OpenProcessToken"
,"OpenThreadToken"
,"OpenWindowStation"
,"PasswordDeriveBytes"
,"Properties"
,"ProtectedEventLogging"
,"PtrToString"
,"PtrToStructure"
,"ReadProcessMemory"
,"ReflectedType"
,"RevertToSelf"
,"RijndaelManaged"
,"ScriptBlockLogging"
,"SetInformationProcess"
,"SetThreadToken"
,"SHA1Managed"
,"StructureToPtr"
,"ToBase64String"
,"TransformFinalBlock"
,"TypeHandle"
,"TypeInitializer"
,"UnderlyingSystemType"
,"UnverifiableCodeAttribute"
,"VirtualAlloc"
,"VirtualFree"
,"VirtualProtect"
,"WriteByte"
,"WriteInt32"
,"WriteProcessMemory"
,"ZeroFreeGlobalAllocUnicode"];
let excludedProcess = datatable(name:string)[@'exclusion1','exclusion2'];
let excludedCommandLines = datatable(name:string)[@'exclusion1',@'exclusion2'];
DeviceProcessEvents 
| where ( InitiatingProcessCommandLine has_any (dirtyWordList) or ProcessCommandLine has_any (dirtyWordList) ) 
| where not ( FileName has_any (excludedProcess) or InitiatingProcessFileName has_any (excludedProcess) or InitiatingProcessParentFileName has_any (excludedProcess) ) or ( InitiatingProcessCommandLine has_any (excludedCommandLines) or ProcessCommandLine has_any (excludedCommandLines) )
```













