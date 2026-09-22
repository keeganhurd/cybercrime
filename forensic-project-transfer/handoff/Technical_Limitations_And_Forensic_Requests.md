# Technical Limitations And Forensic Requests

- Messages.html is an UltData/phone-message HTML export. It supports direction inference but is not the native iPhone database.
- The thread label is `TO: Mom`.
- Recipient/Mom number visible in export text as 13863470544, consistent with 1-386-347-0544. Source/exported device number visible in export text as 623 418 0848. These are not exposed in Messages.html as clean structured sender/recipient handles.
- Need native `sms.db`, handle table, message table, attachment table, attachment GUIDs, transfer metadata, and deletion status.
- Need Apple/iCloud Photos and Messages metadata.
- Need Google Gmail/Drive/account access logs, IPs, user agents, and sessions.
- Need POPD Axon interview/audio/video and official supplemental report.
- Need phone possession/custody/school timeline.
- Do not rely on filesystem created/modified times alone because derivative/export/AirDrop copies may exist.


## UltData Export / Filename Clarification

Messages.html is an UltData/phone-message HTML export. Some media files may have export-generated names such as IMG_####.png or may exist in the Messages/HTML/media folder. Other files have timestamped screenshot filenames. Where these files share the same hash or are otherwise mapped by the cross-folder analysis, they are treated as representations of the same image content. The native iPhone Messages database is needed to determine the original on-device attachment filename, attachment GUID, transfer metadata, deletion status, and exact sender/recipient handles.

## Corrected Event Count Clarification

This packet should refer to 97 unique screenshot-send events within 0-30 seconds. Additional master-index rows may reflect duplicate/cross-folder/export entries. The real-world screenshot/document count appears to be approximately 100-105, subject to forensic confirmation.
