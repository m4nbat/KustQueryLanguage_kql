# MDE Smartscreen Events

Source: https://twitter.com/ellishlomo/status/1655097765565722629

```
let SmartScreenActions = dynamic([
"SmartScreenAppWarning",
"SmartScreenExploitWarning",
"SmartScreenUrlWarning",
"SmartScreenUserOverride"
]);
DeviceEvents
| where ActionType has_any (SmartScreenActions)
```
