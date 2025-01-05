# Day 5 - A basic join of two tables

## Description

The below query provides an example of how to join two tables that share a common field called hostname

``` KQL

FileCreationEvents
| join Employees on $left.hostname == $right.hostname

```