# Day 1 - Decode base64 with KQL

## Description

The below query provides an example of how the base64_decode_tostring() function can be used to decode a field value that is base64 encoded

``` KQL

let base64 = "SW52b2tlLVdtaU1ldGhvZCAtQ29tcHV0ZXJOYW1lICRTZXJ2ZXIgLUNsYXNzIENDTV9Tb2Z0d2FyZVVwZGF0ZXNNYW5hZ2VyIC1OYW1lIEluc3RhbGxVcGRhdGVzIC0gQXJndW1lbnRMaXN0ICgsICRQZW5kaW5nVXBkYXRlTGlzdCkgLU5hbWVzcGFjZSByb290WyZjY20mXWNsaWVudHNkayB8IE91dC1OdWxs";
print base64_decode_tostring(base64)

```