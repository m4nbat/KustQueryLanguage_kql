# Day 6 - Search alerts for Microsoft Threat Actor names

## Description

The below query provides an example of how to search alerts for Microsoft Threat Actor names. This can be used to understand if there have been any alerts related to Microosft TAs in your environement.

``` KQL

let TANames = datatable(PreviousName: string)[
"Typhoon",
"Sandstorm",
"Rain",
"Sleet",
"Blizzard",
"Hail",
"Dust",
"Cyclone",
"Tempest",
"Tsunami",
"Flood",
"Storm-"];
SecurityAlert
| where AlertName has_any (TANames)
 
```
