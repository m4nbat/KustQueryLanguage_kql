

// VMWare hypervisor escape possibilities. Checks for VMs that could have CVEs associated with local privilege escalation
let VMWareVM = DeviceProcessEvents 
| where FileName has "vmtoolsd.exe" or FileName has "vmwaretray.exe" 
| distinct DeviceId;
DeviceTvmSoftwareVulnerabilities
| where DeviceId in~ (VMWareVM)
| where CveId in~ ("CVE-2025-21418","CVE-2025-21391") // replace with LPE CVE IDs of your choosing
