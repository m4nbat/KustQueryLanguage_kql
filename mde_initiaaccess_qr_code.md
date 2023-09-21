EmailEvents
| where SenderDisplayName contains "<company name>"
| where AttachmentCount == 2
| join EmailAttachmentInfo on NetworkMessageId
| where FileName matches regex @"[A-Z]{10}\.png"
| where EmailDirection == 'Inbound'
