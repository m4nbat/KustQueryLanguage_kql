# MDE Tampering Event

# Source: https://twitter.com/ellishlomo/status/1653622838949969925

```
DeviceEvents
| where ActionType == "TamperingAttempt"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend Status = AdditionalInfo.['Status']
| extend Target = AdditionalInfo.['Target']
```
