let clientkeyword = datatable(name:string)["client1","client2","client3","axip","elutia"]; //add clients
let supplierkeyword = datatable(supplier:string)["supplier1","supplier2","supplier3","merchant.id"]; //add suppliers
let victims = externaldata(country:string,
        description:string,
        Country:string,
        discovered:string,
        group_name:string,
        post_title:string,
        post_url:string,
        published:string,
        screenshot:string,
        website:string)
[h@"https://api.ransomware.live/recentvictims"]
with(format="multijson",ignoreFirstRecord=false);
victims
| where post_title has_any (clientkeyword) or post_title has_any (supplierkeyword)
