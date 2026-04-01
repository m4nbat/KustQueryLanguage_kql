# QR Phishing Identification

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566.001 | Phishing: Spearphishing Attachment | [Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |

#### Description
Detection analytics to identify QR code phishing attempts in email. The queries look for image file attachments matching QR code naming patterns and emails with specific attachment characteristics commonly associated with QR phishing campaigns.

#### Risk
QR code phishing bypasses traditional URL-based email filters by embedding malicious URLs inside images. Attackers use QR codes to redirect victims to credential harvesting pages or malware downloads, making these attacks harder to detect with conventional link-scanning tools.

#### Author <Optional>
- **Name:**
- **Github:**
- **Twitter:**
- **LinkedIn:**
- **Website:**

#### References
- [Microsoft Sentinel SOC 101: How to detect QR phishing](https://rodtrent.substack.com/p/microsoft-sentinel-soc-101-how-to-b94)

## Defender For Endpoint
```KQL
let image_extensions = dynamic(["jpg", "jpeg", "png", "bmp", "gif"]);
EmailAttachmentInfo
| where FileType in (image_extensions)
| where FileName matches regex "[A-Z0-9]{9,10}.[A-Za-z0-9]+$"
| join EmailUrlInfo on TenantId
| where UrlLocation == "Attachment"
| distinct FileName, FileType, SenderFromAddress, RecipientEmailAddress, UrlDomain, Url
```

```KQL
EmailEvents
| where AttachmentCount == 2
| join EmailAttachmentInfo on NetworkMessageId
| where FileName matches regex @"[A-Z]{9,10}\.(png|jpeg|jpg|bmp|gif)"
| where EmailDirection == 'Inbound'
```
