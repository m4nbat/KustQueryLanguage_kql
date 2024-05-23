// Look for anomalous emails being received that contain keywords in the subject linked to email bombing campaigns
EmailEvents
| where EmailDirection == "Inbound" and Subject has_all ("subscription","confirm")
| make-series Emailcount = count()
    on Timestamp
    step 1h
    by RecipientObjectId, SourceTenant = TenantId
| extend (Anomalies, AnomalyScore, ExpectedEmails) = series_decompose_anomalies(Emailcount)
| mv-expand Emailcount, Anomalies, AnomalyScore, ExpectedEmails to typeof(double), Timestamp
| where Anomalies != 0
| where AnomalyScore >= 10 // can be tweaked to suit each hunt
| where Emailcount > 5  // only return instances where there are more than 5 emails in the period with the subject keyword matches
 
// Search for the email results based on the results f the above query
EmailEvents
| where RecipientObjectId in ("ENTER YOUR OBJECT ID E.G. 71d04be0-d33f-4cc1-a097-7086d7c7069d")
| where Subject has_all ("subscription","confirm") // Mirror the keywords you used for the original anomaly hunt
 
//Search for quick assist usage in the environment
DeviceNetworkEvents
| where InitiatingProcessCommandLine contains "QuickAssist.exe" and RemoteUrl contains "remoteassistance.support.services.microsoft.com"
 
// Follow-on activity leading to Black Basta ransomware - curl activity
let commands = datatable(command:string)["o","insecure","http"];
let net_iocs = datatable(ioc:string)["upd7","upd7a","upd9","upd5","github"];
DeviceNetworkEvents
| where TimeGenerated > ago(25m)
| where (InitiatingProcessVersionInfoOriginalFileName =~ "curl.exe" or InitiatingProcessFileName =~ "curl.exe") and InitiatingProcessCommandLine has_any (file_ext) and InitiatingProcessCommandLine matches regex @"(upd7.|upd7a.|upd9.|upd5.)"
