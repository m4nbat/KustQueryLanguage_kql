# Queries from the Red Canary November Threat Blog:

# JavaScript .js files executing from optical disc image ISOs
`//Detection opportunity: JavaScript .js files executing from optical disc image ISOs
//The following detection analytic identifies .js files executing from drives other than the default C:\ drive. Malware such as Qbot can be introduced through ISOs that contain malicious .js files. It is rare for .js files to execute from a drive other than the default drive. Since this may occur legitimately if the endpoint’s main partition is not on C:\: additional review may be needed to determine if this is malicious behavior.
// https://redcanary.com/blog/intelligence-insights-november-2022/
DeviceProcessEvents
| where FolderPath !startswith "c:" and FolderPath !startswith "/" and InitiatingProcessFolderPath !startswith "c:" and InitiatingProcessFolderPath !startswith "/" and FolderPath !startswith "\\\\" and InitiatingProcessFolderPath !startswith "\\\\" and isnotempty(InitiatingProcessFolderPath) and isnotempty(FolderPath) and FileName endswith ".js"`
