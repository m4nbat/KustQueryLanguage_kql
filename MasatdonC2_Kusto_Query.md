# Mastodon used for C2

# Instructions:
Generate mastodon API bearer token to enumerate the servers to do this visit Mastodon instances at: https://instances.social/api/token#

# Query to enumerate the API

`curl -H 'Authorization: Bearer BBltUK9rXaGnXnFz2DYuPlybYwOw2ukriRWLIC6fyTO9BQWKkuhNAUZoOn5FTurGm72R9ELpihpeKBKC9w1MeRK4GvwrpmRlxc5neTZgzlE9fQ8zG2XfofJPgfvyJ0Ki' 'https://instances.social/api/1.0/instances/list?count=0' | jq ".instances[].name" | tr -d '"' > mastodon_servers.json`

# Upload the results to Github or a storage account etc and then use the KQL external `data opperator` to use the list in your query.

# Example Hunt Query

`let exclusions = datatable (filepattern:string)["mastodon.exe","Discord.exe","firefox.exe","msedge.exe","chrome.exe","telegram.exe","brave.exe","ExpressConnectNetworkService.exe","sidekick.exe"];
let mastodonServers1 = externaldata (domain:string)[@'https://raw.githubusercontent.com/m4nbat/mastodon_servers/main/mastodon_1-9999.txt'];
let mastodonServers2 = externaldata (domain:string)[@'https://raw.githubusercontent.com/m4nbat/mastodon_servers/main/mastodon_10000-17175.txt'];
// e.g. let iocs = externaldata (ip:string, hash:string, domain:string)[@'https://my-external-lookup.com/ioc.csv'];
//to generate mastodon bearer token go here: https://instances.social/api/token#
// to grab all mastodon servers use: curl -H 'Authorization: Bearer BBltUK9rXaGnXnFz2DYuPlybYwOw2ukriRWLIC6fyTO9BQWKkuhNAUZoOn5FTurGm72R9ELpihpeKBKC9w1MeRK4GvwrpmRlxc5neTZgzlE9fQ8zG2XfofJPgfvyJ0Ki' 'https://instances.social/api/1.0/instances/list?count=0' | jq ".instances[].name" | tr -d '"' > mastodon_servers.json
DeviceNetworkEvents
| where TimeGenerated > ago(14d)
| where RemoteUrl has_any (iocs) or RemoteUrl has_any (mastodonServers2)
| where InitiatingProcessFileName !in~ (exclusions)`
