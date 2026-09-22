# Event Count Clarification Report

The packet identifies 97 unique screenshot-send events within 0-30 seconds. Additional master-index rows reflect duplicate or cross-folder file representations, including timestamped screenshot files and UltData HTML/media files. These should not be counted as additional screenshots unless a unique hash/timestamp/content record supports that conclusion.

## Corrected Counts

- Unique screenshot-send events in `Unique_Capture_Send_Events.csv`: 101
- Unique immediate 0-30 second screenshot-send events: 97
- Unique document/PDF transmission events separately represented: 1
- Master exhibit index rows: 203
- Duplicate/cross-folder/export rows or non-unique representations by comparison: approximately 101
- Real-world screenshot/document count appears to be approximately 100-105, subject to forensic confirmation.

## Exhibits, Files, Rows, And Events

An exhibit index row is not always a unique real-world screenshot capture. Some rows are timestamped screenshot files, some are UltData HTML/media files, and some are duplicate/cross-folder/export representations of the same image content. A unique capture-send event is grouped primarily by SHA256, with timestamp/message/content context used for interpretation.

## Timestamped Screenshot Files Versus UltData HTML/Media Files

Messages.html is an UltData/phone-message HTML export. Some media files may have export-generated names such as IMG_####.png or may exist in the Messages/HTML/media folder. Other files have timestamped screenshot filenames. Where these files share the same hash or are otherwise mapped by the cross-folder analysis, they are treated as representations of the same image content. The native iPhone Messages database is needed to determine the original on-device attachment filename, attachment GUID, transfer metadata, deletion status, and exact sender/recipient handles.

Duplicate files do not weaken the evidence. They show the same content appearing in multiple export locations. However, duplicate rows must not be counted as separate screenshot captures without unique hash/timestamp/content support.

## Native Confirmation

Native iPhone database confirmation remains necessary to determine original on-device attachment filename, attachment GUID, sender/recipient handles, transfer metadata, deletion status, and actor attribution.
