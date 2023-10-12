# DarkGate MDE Detetcions

# Source (Intrusion Analysis)

# Port and HTTP request based detection

```
DeviceNetworkEvents
| where TimeGenerated > ago(60d)
| extend HTTPMethod = tostring(AdditionalFields.method)
| where ActionType =~ "HttpConnectionInspected" and RemotePort == 2351 and HTTPMethod =~ "POST"
| extend direction = tostring(AdditionalFields.direction)
| extend host = tostring(AdditionalFields.host)
| extend request_body_len = tostring(AdditionalFields.request_body_len)
| extend response_body_len = tostring(AdditionalFields.response_body_len)
| extend status_code = tostring(AdditionalFields.status_code)
| extend status_msg = tostring(AdditionalFields.status_msg)
| extend tags = tostring(parse_json(tostring(AdditionalFields.tags)))
| extend trans_depth = tostring(AdditionalFields.trans_depth)
| extend uri = tostring(AdditionalFields.uri)
| extend user_agent = tostring(AdditionalFields.user_agent)
| extend version_ = tostring(AdditionalFields.version)
```
