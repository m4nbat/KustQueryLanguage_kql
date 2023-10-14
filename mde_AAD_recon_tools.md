# Title
AAD Recon Detection Queries

# Sources
https://cloudbrothers.info/en/detect-threats-microsoft-graph-logs-part-1/

# Queries

## Azure Hound UserAgent

```
MicrosoftGraphActivityLogs
| where UserAgent has "azurehound"
| extend ObjectId = iff(isempty(UserId), ServicePrincipalId, UserId)
| extend ObjectType = iff(isempty(UserId), "ServicePrincipalId", "UserId")
| summarize by ObjectId, ObjectType

```

## AzureHound Behavioural

```
  let AzureHoundGraphQueries = dynamic([
      "https:/graph.microsoft.com/version/servicePrincipals/<UUID>/owners",
      "https:/graph.microsoft.com/version/groups/<UUID>/members",
      "https:/graph.microsoft.com/version/groups/<UUID>/owners",
      "https:/graph.microsoft.com/version/servicePrincipals/<UUID>/appRoleAssignedTo",
      "https:/graph.microsoft.com/version/roleManagement/directory/roleAssignments",
      "https:/graph.microsoft.com/version/applications/<UUID>/owners",
      "https:/graph.microsoft.com/version/devices/<UUID>/registeredOwners",
      "https:/graph.microsoft.com/version/organization",
      "https:/graph.microsoft.com/version groups",
      "https:/graph.microsoft.com/version/servicePrincipals",
      "https:/graph.microsoft.com/version/applications",
      "https:/graph.microsoft.com/version/roleManagement/directory/roleDefinitions",
      "https:/graph.microsoft.com/version/devices",
      "https:/graph.microsoft.com/version/users"
      ]);
  let PotentialMaliciousGraphCalls = materialize (
      MicrosoftGraphActivityLogs
      | where ingestion_time() > ago(35m)
      | extend ObjectId = iff(isempty(UserId), ServicePrincipalId, UserId)
      | extend ObjectType = iff(isempty(UserId), "ServicePrincipalId", "UserId")
      | where RequestUri !has "microsoft.graph.delta"
      | extend NormalizedRequestUri = replace_regex(RequestUri, @'[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}', @'<UUID>')
      | extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\d+$', @'<UUID>')
      | extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/+', @'/')
      | extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/(v1\.0|beta)\/', @'/version/')
      | extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'%23EXT%23', @'')
      | extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/[a-zA-Z0-9+_.\-]+@[a-zA-Z0-9.]+\/', @'/<UUID>/')
      | extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'^\/<UUID>', @'')
      | extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\?.*$', @'')
      | summarize
          GraphEndpointsCalled = make_set(NormalizedRequestUri, 1000),
          IPAddresses = make_set(IpAddress)
          by ObjectId, ObjectType
      | project
          ObjectId,
          ObjectType,
          IPAddresses,
          MatchingQueries=set_intersect(AzureHoundGraphQueries, GraphEndpointsCalled)
      | extend ConfidenceScore = round(todouble(array_length(MatchingQueries)) / todouble(array_length(AzureHoundGraphQueries)), 1)
      | where ConfidenceScore > 0.7);
  let IPEntities = PotentialMaliciousGraphCalls
      | mv-expand IPAddresses
      | sort by ObjectId
      | extend CurrentRowNumber=row_number(2, prev(ObjectId) != ObjectId)
      | extend IPInformation = bag_pack(@"$id", CurrentRowNumber, "Address", IPAddresses, "Type", "ip")
      | project ObjectId, IPInformation
      | summarize IPInformation = make_set(IPInformation, 150) by ObjectId;
  PotentialMaliciousGraphCalls
  | join kind=leftouter IPEntities on ObjectId
  | project-away IPAddresses, *1, *2

```

## PurpleKnight Behavioral

```
let GraphQueries = dynamic([ "https:/graph.microsoft.com/version/servicePrincipals/<UUID>/appRoleAssignments", "https:/graph.microsoft.com/version/roleManagement/directory/roleEligibilityScheduleInstances", "https:/graph.microsoft.com/version/servicePrincipals/", "https:/graph.microsoft.com/version/roleManagement/directory/roleAssignments", "https:/graph.microsoft.com/version/users/<UUID>/memberOf", "https:/graph.microsoft.com/version/directoryRoles/roleTemplateId=<UUID>/members", "https:/graph.microsoft.com/version/directoryObjects/<UUID>", "https:/graph.microsoft.com/version/identity/conditionalAccess/policies", "https:/graph.microsoft.com/version/policies/authorizationPolicy", "https:/graph.microsoft.com/version/policies/identitySecurityDefaultsEnforcementPolicy", "https:/graph.microsoft.com/version/organization", "https:/graph.microsoft.com/version/users", "https:/graph.microsoft.com/version/reports/credentialUserRegistrationDetails", "https:/graph.microsoft.com/version/directoryRoles", "https:/graph.microsoft.com/version/identity/conditionalAccess/namedLocations", "https:/graph.microsoft.com/version/auditLogs/signIns", "https:/graph.microsoft.com/version/$batch", "https:/graph.microsoft.com/version/roleManagement/directory/roleAssignmentScheduleRequests", "https:/graph.microsoft.com/version/directory/administrativeUnits", "https:/graph.microsoft.com/version/settings", "https:/graph.microsoft.com/version/applications", "https:/graph.microsoft.com/version/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator", "https:/graph.microsoft.com/version/servicePrincipals" ]);
let PotentialMaliciousGraphCalls = materialize (
MicrosoftGraphActivityLogs
| where ingestion_time() > ago(35m)
| extend ObjectId = iff(isempty(UserId), ServicePrincipalId, UserId)
| extend ObjectType = iff(isempty(UserId), "ServicePrincipalId", "UserId")
| where RequestUri !has "microsoft.graph.delta"
| extend NormalizedRequestUri = replace_regex(RequestUri, @'[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}', @'<UUID>')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\d+$', @'<UUID>')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/+', @'/')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/(v1\.0|beta)\/', @'/version/')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'%23EXT%23', @'')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\/[a-zA-Z0-9+_.\-]+@[a-zA-Z0-9.]+\/', @'/<UUID>/')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'^\/<UUID>', @'')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\?.*$', @'')
| summarize GraphEndpointsCalled = make_set(NormalizedRequestUri, 1000), IPAddresses = make_set(IpAddress) by ObjectId, ObjectType
| project ObjectId, ObjectType, IPAddresses, MatchingQueries=set_intersect(GraphQueries, GraphEndpointsCalled)
| extend ConfidenceScore = round(todouble(array_length(MatchingQueries)) / todouble(array_length(GraphQueries)), 1)
| where ConfidenceScore > 0.7); let IPEntities = PotentialMaliciousGraphCalls
| mv-expand IPAddresses
| sort by ObjectId
| extend CurrentRowNumber=row_number(2, prev(ObjectId) != ObjectId)
| extend IPInformation = bag_pack(@"$id", CurrentRowNumber, "Address", IPAddresses, "Type", "ip")
| project ObjectId, IPInformation
| summarize IPInformation = make_set(IPInformation, 150) by ObjectId; PotentialMaliciousGraphCalls
| join kind=leftouter IPEntities on ObjectId
| project-away IPAddresses, *1, *2

```



