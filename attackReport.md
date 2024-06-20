# MITRE ATT&CK Reporting

let enterpriseAttack = externaldata (type:string, id:string, objects:dynamic)[h@"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"]
with (format="multijson");
enterpriseAttack
| mv-expand objects
| extend objectType = tostring(objects.type)
| extend objectId = tostring(objects.id)
| where objectType =~ "attack-pattern" //and  attackTechnique matches regex @"T[0-9]{4}(|\.[0-9]{3})"
| extend attackTechnique = parse_json(tostring(objects.external_references))[0].external_id
| extend attackTechniqueName = tostring(objects.name)
| extend attackUrl = parse_json(tostring(objects.external_references))[0].url
| extend killchainPhases = parse_json(objects.kill_chain_phases)
| extend dataSources = parse_json(objects.x_mitre_data_sources)
| extend detectionAdvice = parse_json(objects.x_mitre_detection)
| project attackTechnique, attackTechniqueName, attackUrl, killchainPhases, dataSources, detectionAdvice, objectId, objectType, type, objects
