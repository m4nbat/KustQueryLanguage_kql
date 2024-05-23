Sandworm - ShadowLink

//Malware related alert for this variant:
SecurityAlert
| where AlertName contains "ShadowLink"

//Persistence:
DeviceEvents
| where ActionType == 'ServiceInstalled'
| extend JSON = parse_json(AdditionalFields)
| where JSON.ServiceName has 'tor'
| extend SourceTenant = TenantId
| join kind=leftouter tid_lookup on $left.SourceTenant == $right.id
| project-away id
| summarize count() by name
