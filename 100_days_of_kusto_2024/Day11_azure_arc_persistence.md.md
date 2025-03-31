Defender For Endpoint
// Unexpected installation of azure arc agent - service installation
let ServiceNames = datatable(name:string)["himds.exe","gc_arc_service.exe","gc_extension_service.exe"];
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| extend ServiceAccount = tostring(parse_json(AdditionalFields).ServiceAccount)
| extend ServiceStartType = tostring(parse_json(AdditionalFields).ServiceStartType)
| extend ServiceType = tostring(parse_json(AdditionalFields).ServiceType)
| where ServiceName has_any (ServiceNames)
// Unexpected installation of azure arc agent - filepaths
let AzureArcServicePaths = datatable(name:string)[@"\\AzureConnectedMachineAgent\\GCArcService\\GC"];
DeviceFileEvents
| where ActionType =~ "FileCreated"
| where FolderPath  has_any (AzureArcServicePaths)
