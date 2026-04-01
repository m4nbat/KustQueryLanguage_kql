# MITRE ATT&CK Framework Reporting Query

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T0000 | MITRE ATT&CK Framework Reference | [MITRE ATT&CK](https://attack.mitre.org/) |

#### Description
Query to pull all MITRE ATT&CK enterprise techniques from the MITRE CTI GitHub repository. Useful for ATT&CK-based reporting and detection coverage analysis.

#### Risk
This utility query provides a comprehensive view of the MITRE ATT&CK framework for reporting and gap analysis.

#### Author <Optional>
- **Name:** Gavin Knapp
- **Github:** https://github.com/m4nbat 
- **Twitter:** https://twitter.com/knappresearchlb
- **LinkedIn:** https://www.linkedin.com/in/grjk83/
- **Website:**

#### References
- https://github.com/mitre/cti
- https://attack.mitre.org/

## Defender For Endpoint
```KQL
let enterpriseAttack = externaldata (type:string, id:string, objects:dynamic)[h@"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"]
with (format="multijson");
enterpriseAttack
| mv-expand objects
| extend objectType = tostring(objects.type)
| extend objectId = tostring(objects.id)
| where objectType =~ "attack-pattern"
| extend attackTechnique = parse_json(tostring(objects.external_references))[0].external_id
| extend attackTechniqueName = tostring(objects.name)
| extend attackUrl = parse_json(tostring(objects.external_references))[0].url
| extend killchainPhases = parse_json(objects.kill_chain_phases)
| extend dataSources = parse_json(objects.x_mitre_data_sources)
| extend detectionAdvice = parse_json(objects.x_mitre_detection)
| project attackTechnique, attackTechniqueName, attackUrl, killchainPhases, dataSources, detectionAdvice, objectId, objectType, type, objects
```

## Sentinel
```KQL
let enterpriseAttack = externaldata (type:string, id:string, objects:dynamic)[h@"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"]
with (format="multijson");
enterpriseAttack
| mv-expand objects
| extend objectType = tostring(objects.type)
| extend objectId = tostring(objects.id)
| where objectType =~ "attack-pattern"
| extend attackTechnique = parse_json(tostring(objects.external_references))[0].external_id
| extend attackTechniqueName = tostring(objects.name)
| extend attackUrl = parse_json(tostring(objects.external_references))[0].url
| extend killchainPhases = parse_json(objects.kill_chain_phases)
| extend dataSources = parse_json(objects.x_mitre_data_sources)
| extend detectionAdvice = parse_json(objects.x_mitre_detection)
| project attackTechnique, attackTechniqueName, attackUrl, killchainPhases, dataSources, detectionAdvice, objectId, objectType, type, objects
```
