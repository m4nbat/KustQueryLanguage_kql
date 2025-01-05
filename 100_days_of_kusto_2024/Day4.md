# Day 4 - Using let statements

## Description

Basic use of let statement to build a table of values that can be used in a subsequent query

``` KQL

let mary_ips = //sets a variable called marey_ips
Employees  //use the Employees table
| where name has "Mary" //filter results to those that have Mary in the name field
| distinct ip_addr; //output a distinct list of IP addresses assigned to users called Mary the ; ends the let statement
OutboundNetworkEvents // use the OutboundNetworkEvents table
| where src_ip in~ (mary_ips) // filter on the src_ip field using the ips we produced in our let statement
| summarize dcount(url) // provide a distinct count of urls visited by IP addresses assigned to Mary's

```