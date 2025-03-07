# Day 8 - Active exploitation of VMware ESX hypervisor escape ESXicape

## Description

Yesterday, VMware quietly released patches for three ESXi zero day vulnerabilities: CVE-2025–22224, CVE-2025–22225, CVE-2025–22226. Thsi KQL allows you to identify VMWare virtual machines in your environment.

### Example Script

```



```

## References
https://cyberplace.social/@GossiTheDog/114114843502983550
https://doublepulsar.com/use-one-virtual-machine-to-own-them-all-active-exploitation-of-esxicape-0091ccc5bdfc

## Query MDE

``` KQL

// VMWare hypervisor escape possibilities. Checks for VMs that could have CVEs associated with local privilege escalation
let VMWareVM = DeviceProcessEvents 
| where FileName has "vmtoolsd.exe" or FileName has "vmwaretray.exe" 
| distinct DeviceId;
DeviceTvmSoftwareVulnerabilities
| where DeviceId in~ (VMWareVM)
| where CveId in~ ("CVE-2025-21418","CVE-2025-21391") // replace with LPE CVE IDs of your choosing

```


