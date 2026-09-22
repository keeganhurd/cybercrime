## Timing Contradiction With Later-Discovery Explanation

Robin's reported POPD statement describes a parental sweep of Elijah's phone, later discovery of shared photos/financial documents, screenshoting documents, and providing them to attorney Christopher Ditslear. Her October 1, 2024 testimony states that she was able to find financial statements, business names, EIN numbers, bank statements, and the like.

The technical timeline creates a material timing issue with a simple later-discovery explanation. The lead screenshot filename timestamp is `2024-04-19 19:22:24`, and the Messages.html/texted-to-Mom timestamp is `2024/04/19 19:22:35`, an approximately 11-second gap. The packet verifies 97 screenshot-send events within 0-30 seconds.

This timing pattern strongly undermines a simple explanation that the images were merely discovered later in Photos. The repeated 0-30 second gaps are more consistent with immediate capture-and-send conduct by the person possessing the phone. Native iPhone database confirmation is still required for sender/recipient handles, attachment GUIDs, and actor attribution. POPD should compare this timeline against Robin's Axon interview and the native iPhone message database.


## UltData Export / Filename Clarification

Messages.html is an UltData/phone-message HTML export. Some media files may have export-generated names such as IMG_####.png or may exist in the Messages/HTML/media folder. Other files have timestamped screenshot filenames. Where these files share the same hash or are otherwise mapped by the cross-folder analysis, they are treated as representations of the same image content. The native iPhone Messages database is needed to determine the original on-device attachment filename, attachment GUID, transfer metadata, deletion status, and exact sender/recipient handles.

## Corrected Event Count Clarification

This packet should refer to 97 unique screenshot-send events within 0-30 seconds. Additional master-index rows may reflect duplicate/cross-folder/export entries. The real-world screenshot/document count appears to be approximately 100-105, subject to forensic confirmation.
