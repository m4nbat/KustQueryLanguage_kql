# QR Phishing Identification

# Sources:
https://rodtrent.substack.com/p/microsoft-sentinel-soc-101-how-to-b94

```
let image_extensions = dynamic(["jpg", "jpeg", "png", "bmp", "gif"]);
EmailAttachmentInfo
| where FileType in (image_extensions)
| where FileName matches regex "[A-Z0-9]{9,10}.[A-Za-z0-9]+$"
| join EmailUrlInfo on TenantId
| where UrlLocation == "Attachment"
| distinct FileName, FileType, SenderFromAddress, RecipientEmailAddress, UrlDomain, Url
```

```
EmailEvents
| where AttachmentCount == 2
| join EmailAttachmentInfo on NetworkMessageId
| where FileName matches regex @"[A-Z]{9,10}\.(png|jpeg|jpg|bmp|gif)"
| where EmailDirection == 'Inbound'
```
