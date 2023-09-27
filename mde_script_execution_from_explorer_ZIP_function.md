

//The following detection analytic identifies scripts executed from the built-in explorer.exe ZIP folder function. Adversaries like Scarlet Goldfinch often compress malicious scripts via a ZIP file in an attempt to evade network-based security products. Investigating follow-on file modifications, registry modifications, and child processes related to this behavior can help determine if it is malicious or legitimate.
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "wscript.exe" and ( InitiatingProcessCommandLine has_any ("users","temp") and InitiatingProcessCommandLine has_any (".zip",".js") )

//The following detection analytic identifies scripts executed from the built-in explorer.exe ZIP folder function. Adversaries like Scarlet Goldfinch often compress malicious scripts via a ZIP file in an attempt to evade network-based security products. Investigating follow-on file modifications, registry modifications, and child processes related to this behavior can help determine if it is malicious or legitimate.
DeviceProcessEvents
| where InitiatingProcessParentFileName =~ "explorer.exe" and InitiatingProcessFileName =~ "wscript.exe" and ( InitiatingProcessCommandLine has_any ("users","temp") and InitiatingProcessCommandLine has_any (".zip",".js") )
