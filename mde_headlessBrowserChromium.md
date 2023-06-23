#  Chromium Based Headless browser download

# Description
detection analytic looks for Chromium-based browsers opening with the headless parameter and subsequently downloading files from a remote location. While developers may use headless browsers to download files, it is an unusual way to do so. This analytic can help identify Ducktail as well as other suspicious activity.

# Source
https://redcanary.com/blog/intelligence-insights-june-2023/

# Analytics

## MDE

Analytic to identify chromium-based headless browsers being used to download files. Can identify Ducktail infostealer and other unusual activity.

```
// Chromium-based headless browsers being used to download files. Can identify Ducktail infostealer and other unusual activity.
// https://redcanary.com/blog/intelligence-insights-june-2023/?utm_source=redcanary&utm_medium=email&utm_campaign=Blog%20Digest-2023-06-23T09:00:07.795-06:00&mkt_tok=MDAzLVlSVS0zMTQAAAGMh8L-8o-_Q9SP1hoJeNiD2eROhNCDfE-o9-mzCwm2WWNKCJBsCemaZGtIk0Z6CPB6HvtJ3Tw56zP18g_5eysElp6SPgKrW6DFYNQtuLYKRZY
let args = datatable(name:string)["--headless","--dump-dom","http"];
let chromiumBrowsers = datatable(name:string)["chrome.exe","msedge.exe"]; //add others
DeviceProcessEvents
| where (InitiatingProcessFileName has_any (chromiumBrowsers) or FileName has_any (chromiumBrowsers)) and (InitiatingProcessCommandLine has_all (args) or ProcessCommandLine has_all (args))
```
