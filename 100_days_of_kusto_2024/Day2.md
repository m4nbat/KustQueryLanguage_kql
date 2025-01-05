# Day 1 - calculating the difference between two dates using kql

## Description

The below query provides an example of how to calculate teh difference between two date values using kql

``` KQL

let emailRecieved = datetime("2024-01-31T11:11:12Z");
let fileExecuted = datetime("2024-01-31T10:26:20Z");
print fileExecuted - emailRecieved

```