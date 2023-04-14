# Detect use of RClone to compress and exfiltrate data

```
let Rclone_Commands = dynamic(["pass","user","copy","mega","sync","config","lsd","remote","ls"]);
    DeviceProcessEvents
    | where FileName contains "rclone"
    | where ProcessCommandLine has_any (Rclone_Commands)
```
