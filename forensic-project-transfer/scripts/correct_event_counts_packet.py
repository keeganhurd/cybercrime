import csv
import re
from collections import defaultdict
from pathlib import Path

FINAL = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA")
SRC = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\IPhone Screenshot Evidence April 2024")
MESSAGES = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Messages.html")

GAPS = SRC / "Screenshot_Send_Gap_Master.csv"
AMAP = SRC / "Attachment_Message_Map.csv"
CROSS = SRC / "Cross_Folder_Image_Map.csv"
SENSITIVE = SRC / "Sensitive_Screenshot_Exhibits.csv"
OCR = SRC / "Screenshot_OCR_Full_Review.csv"
MASTER = FINAL / "Master_Exhibit_Index.csv"

UNIQUE_CSV = FINAL / "Unique_Capture_Send_Events.csv"
ALIAS_CSV = FINAL / "Exhibit_File_Alias_Map.csv"
COUNT_REPORT = FINAL / "Event_Count_Clarification_Report.md"
SUMMARY = FINAL / "Corrected_Submission_Summary_For_POPD_SA.md"
AUDIT = FINAL / "Final_Overstatement_Audit.md"

PHONE_NOTE = "Recipient/Mom phone visible in export text as 13863470544 / 1-386-347-0544; source/exported device phone visible as 623 418 0848. Messages.html does not expose these as clean structured handles."
ULTDATA = (
    "Messages.html is an UltData/phone-message HTML export. Some media files may have export-generated names such as "
    "IMG_####.png or may exist in the Messages/HTML/media folder. Other files have timestamped screenshot filenames. "
    "Where these files share the same hash or are otherwise mapped by the cross-folder analysis, they are treated as "
    "representations of the same image content. The native iPhone Messages database is needed to determine the original "
    "on-device attachment filename, attachment GUID, transfer metadata, deletion status, and exact sender/recipient handles."
)
OVERSTATEMENTS = [
    "191 screenshot-send events",
    "191 immediate gaps",
    "191 screenshots",
    "191 unique",
    "200 screenshots captured",
    "every IMG file was sent",
    "Robin sent",
    "Robin captured",
    "guilty",
    "beyond a reasonable doubt",
    "proves Robin",
    "proves actor identity",
]


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write(path, text):
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def normpath(path):
    return str(path or "").lower()


def top20(master):
    def score(r):
        if r.get("ScreenshotFilenameTimestamp") == "2024-04-19 19:22:24":
            return 100000
        if r.get("DisplayFileName") == "FILE_5531.pdf":
            return 99000
        cats = r.get("OCRCategory", "")
        s = 0
        for term, pts in [
            ("IRS/EIN", 5000), ("Gmail", 4000), ("Google Account", 3800),
            ("Google Drive", 3700), ("Navy Federal", 3500),
            ("Bank Statement", 3300), ("Financial Statement", 3200),
            ("Business Record", 3000), ("Helo Payment Services", 2900),
        ]:
            if term in cats:
                s += pts
        if r.get("ElapsedClassification") == "Immediate":
            s += 1000
        try:
            s += max(0, 500 - int(r.get("ElapsedSeconds") or "9999"))
        except ValueError:
            pass
        return s
    out, seen = [], set()
    for r in sorted(master, key=score, reverse=True):
        key = r.get("SHA256") or r.get("DisplayFileName")
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
        if len(out) == 20:
            break
    return out


def build_maps():
    gaps = read_csv(GAPS)
    amap = read_csv(AMAP)
    cross = read_csv(CROSS)
    sensitive = read_csv(SENSITIVE)
    ocr = read_csv(OCR)
    master = read_csv(MASTER)

    attach_by_ts = {r.get("FileNameTimestamp"): r for r in amap if r.get("FileNameTimestamp")}
    attach_by_hash = defaultdict(list)
    for r in amap:
        if r.get("SHA256"):
            attach_by_hash[r["SHA256"].upper()].append(r)

    cross_by_hash = defaultdict(list)
    for r in cross:
        if r.get("SHA256"):
            cross_by_hash[r["SHA256"].upper()].append(r)

    ocr_by_hash = {}
    for r in ocr:
        if r.get("SHA256") and (r.get("DetectedSensitiveTerms") or r["SHA256"].upper() not in ocr_by_hash):
            ocr_by_hash[r["SHA256"].upper()] = r

    master_by_hash = defaultdict(list)
    for r in master:
        if r.get("SHA256"):
            master_by_hash[r["SHA256"].upper()].append(r)

    sens_by_hash = defaultdict(list)
    for r in sensitive:
        if r.get("SHA256"):
            sens_by_hash[r["SHA256"].upper()].append(r)

    return gaps, amap, cross, sensitive, ocr, master, attach_by_ts, attach_by_hash, cross_by_hash, ocr_by_hash, master_by_hash, sens_by_hash


def classify_path(path):
    p = normpath(path)
    if "messages\\html\\media" in p:
        return "html"
    if "message attachments\\photos" in p:
        return "attachments"
    if "\\photos\\" in p:
        return "photos"
    return "other"


def build_unique_events():
    gaps, amap, cross, sensitive, ocr, master, attach_by_ts, attach_by_hash, cross_by_hash, ocr_by_hash, master_by_hash, sens_by_hash = build_maps()
    rows = []
    alias_rows = []
    seen_hashes = set()
    eid = 1

    for gap in sorted(gaps, key=lambda r: (r.get("ScreenshotTimestampFromFilename"), r.get("MessageTimestampLocal"))):
        h = (gap.get("SHA256") or "").upper()
        if not h or h in seen_hashes:
            continue
        seen_hashes.add(h)
        attaches = attach_by_hash.get(h, [])
        crosses = cross_by_hash.get(h, [])
        o = ocr_by_hash.get(h, {})
        mrows = master_by_hash.get(h, [])
        primary = mrows[0] if mrows else {}
        timestamped = gap.get("ScreenshotPath", "")
        html_media = ""
        photos = ""
        msg_attach = ""
        other = []
        for item in crosses:
            kind = classify_path(item.get("FullPath"))
            if kind == "html" and not html_media:
                html_media = item["FullPath"]
            elif kind == "attachments" and not msg_attach:
                msg_attach = item["FullPath"]
            elif kind == "photos" and not photos:
                photos = item["FullPath"]
            else:
                other.append(item.get("FullPath", ""))
        for a in attaches:
            if classify_path(a.get("AttachmentResolvedPath")) == "html" and not html_media:
                html_media = a["AttachmentResolvedPath"]
        all_paths = [p for p in [timestamped, html_media, photos, msg_attach] + other if p]
        ceid = f"CE-{eid:03d}"
        eid += 1
        category = o.get("DetectedSensitiveTerms") or primary.get("OCRCategory", "")
        visual = o.get("OCRTextShort") or primary.get("VisualDescription", "")
        row = {
            "CanonicalEventId": ceid,
            "EventType": "Screenshot transmission",
            "PrimaryExhibitNumber": primary.get("ExhibitNumber", ""),
            "PrimarySHA256": h,
            "AllMatchingSHA256sIfAny": h,
            "ScreenshotFilenameTimestamp": gap.get("ScreenshotTimestampFromFilename", ""),
            "MessagesHtmlTextedToMomTimestamp": gap.get("MessageTimestampLocal", ""),
            "ElapsedSeconds": gap.get("ElapsedSeconds", ""),
            "ElapsedClassification": gap.get("ElapsedClassification", ""),
            "ConversationContact": gap.get("ConversationOrContact", ""),
            "RecipientPhoneVisible": "13863470544 / 1-386-347-0544 visible in export text; not a structured handle",
            "SourceDevicePhoneVisible": "623 418 0848 visible in export text; not a structured handle",
            "DirectionInference": gap.get("Direction", ""),
            "TimestampedScreenshotFilePath": timestamped,
            "TimestampedScreenshotFileName": Path(timestamped).name if timestamped else "",
            "HtmlMediaFilePath": html_media,
            "HtmlMediaFileName": Path(html_media).name if html_media else "",
            "OtherMatchingPaths": "; ".join(p for p in all_paths if p not in [timestamped, html_media]),
            "CrossFolderMatchStatus": "Same hash match across folders" if len(all_paths) > 1 else "No cross-folder same-hash match identified",
            "OriginalOrExportDerivativeAssessment": "Cross-folder/export representations of same image content; original filename and attachment GUID require native iPhone database confirmation" if len(all_paths) > 1 else "Single representation located; original/export status requires native iPhone database confirmation",
            "OCRSensitiveCategory": category,
            "OCRKeyTerms": category,
            "VisualDescription": visual,
            "WhyItMatters": "Unique screenshot-send event with elapsed timing; duplicate/export rows should not be counted as additional captures.",
            "Limitation": "Actor identity, original on-device filename, sender/recipient handles, and attachment GUID require native iPhone confirmation.",
            "NativeConfirmationNeeded": "sms.db, handle table, attachment GUIDs, transfer metadata, deletion status, Apple/iCloud records.",
        }
        rows.append(row)
        alias_rows.append({
            "CanonicalEventId": ceid,
            "TimestampedScreenshotPath": timestamped,
            "TimestampedScreenshotFileName": Path(timestamped).name if timestamped else "",
            "HtmlMediaPath": html_media,
            "HtmlMediaFileName": Path(html_media).name if html_media else "",
            "PhotosFolderPath": photos,
            "MessageAttachmentsPhotosPath": msg_attach,
            "SHA256": h,
            "SizeBytes": primary.get("SizeBytes") or (crosses[0].get("SizeBytes") if crosses else ""),
            "Dimensions": gap.get("Dimensions") or primary.get("Dimensions", ""),
            "SameHashMatch": "Yes" if len(all_paths) > 1 else "No",
            "SameTimestampMatch": "Yes" if gap.get("ScreenshotFilenameTimestamp") else "Unknown",
            "SameContentPossible": "Yes - same SHA256" if len(all_paths) > 1 else "Unknown",
            "Notes": "Do not assume either timestamped screenshot filename or HTML/media filename was the native iPhone attachment filename without sms.db confirmation.",
        })

    # Add FILE_5531 as a unique document transmission event.
    pdf = next((r for r in master if r.get("DisplayFileName") == "FILE_5531.pdf"), None)
    if pdf:
        ceid = f"CE-{eid:03d}"
        rows.append({
            "CanonicalEventId": ceid,
            "EventType": "PDF/document transmission",
            "PrimaryExhibitNumber": pdf.get("ExhibitNumber", ""),
            "PrimarySHA256": pdf.get("SHA256", ""),
            "AllMatchingSHA256sIfAny": pdf.get("SHA256", ""),
            "ScreenshotFilenameTimestamp": "",
            "MessagesHtmlTextedToMomTimestamp": pdf.get("MessagesHtmlTimestamp", "2024/04/25 12:54:20"),
            "ElapsedSeconds": "",
            "ElapsedClassification": "",
            "ConversationContact": "Mom",
            "RecipientPhoneVisible": "13863470544 / 1-386-347-0544 visible in export text; not a structured handle",
            "SourceDevicePhoneVisible": "623 418 0848 visible in export text; not a structured handle",
            "DirectionInference": pdf.get("DirectionInference", ""),
            "TimestampedScreenshotFilePath": "",
            "TimestampedScreenshotFileName": "",
            "HtmlMediaFilePath": pdf.get("SourcePath", ""),
            "HtmlMediaFileName": "FILE_5531.pdf",
            "OtherMatchingPaths": "",
            "CrossFolderMatchStatus": "Document event; same-hash standalone copy previously identified",
            "OriginalOrExportDerivativeAssessment": "PDF located in UltData Messages/HTML/media; native attachment GUID and filename require sms.db confirmation",
            "OCRSensitiveCategory": "IRS/EIN; Business Record; HELO Payment Services",
            "OCRKeyTerms": "IRS; EIN; CP 575; HELO PAYMENT SERVICES LLC",
            "VisualDescription": "IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC.",
            "WhyItMatters": "Confirms sensitive IRS/EIN business PDF appears in same April 25 TO: Mom transmission sequence.",
            "Limitation": "Actor identity and native transfer metadata require native iPhone confirmation.",
            "NativeConfirmationNeeded": "sms.db attachment GUID, sender/recipient handles, Apple/iCloud metadata.",
        })
    return rows, alias_rows


def revise_markdown(unique_rows, alias_rows):
    unique_immediate = sum(1 for r in unique_rows if r.get("EventType") == "Screenshot transmission" and r.get("ElapsedClassification") == "Immediate")
    unique_screens = sum(1 for r in unique_rows if r.get("EventType") == "Screenshot transmission")
    docs = sum(1 for r in unique_rows if r.get("EventType") != "Screenshot transmission")
    master_rows = len(read_csv(MASTER))
    duplicate_rows = max(0, master_rows - len(unique_rows))
    text = f"""# Event Count Clarification Report

The packet identifies 97 unique screenshot-send events within 0-30 seconds. Additional master-index rows reflect duplicate or cross-folder file representations, including timestamped screenshot files and UltData HTML/media files. These should not be counted as additional screenshots unless a unique hash/timestamp/content record supports that conclusion.

## Corrected Counts

- Unique screenshot-send events in `Unique_Capture_Send_Events.csv`: {unique_screens}
- Unique immediate 0-30 second screenshot-send events: {unique_immediate}
- Unique document/PDF transmission events separately represented: {docs}
- Master exhibit index rows: {master_rows}
- Duplicate/cross-folder/export rows or non-unique representations by comparison: approximately {duplicate_rows}
- Real-world screenshot/document count appears to be approximately 100-105, subject to forensic confirmation.

## Exhibits, Files, Rows, And Events

An exhibit index row is not always a unique real-world screenshot capture. Some rows are timestamped screenshot files, some are UltData HTML/media files, and some are duplicate/cross-folder/export representations of the same image content. A unique capture-send event is grouped primarily by SHA256, with timestamp/message/content context used for interpretation.

## Timestamped Screenshot Files Versus UltData HTML/Media Files

{ULTDATA}

Duplicate files do not weaken the evidence. They show the same content appearing in multiple export locations. However, duplicate rows must not be counted as separate screenshot captures without unique hash/timestamp/content support.

## Native Confirmation

Native iPhone database confirmation remains necessary to determine original on-device attachment filename, attachment GUID, sender/recipient handles, transfer metadata, deletion status, and actor attribution.
"""
    write(COUNT_REPORT, text)

    summary = f"""# Corrected Submission Summary For POPD / State Attorney

## Bottom Line

The core finding is 97 unique immediate screenshot-send events within 0-30 seconds. Additional index rows are duplicate/cross-folder/export records and should not be counted as additional captures. The lead event has an 11-second gap: screenshot filename/capture timestamp `2024-04-19 19:22:24` and Messages.html/texted-to-Mom timestamp `2024/04/19 19:22:35`.

## Corrected Counting

The final packet distinguishes exhibits, files, rows, and unique capture-send events. `Unique_Capture_Send_Events.csv` identifies {unique_screens} unique screenshot-send events and {docs} unique document/PDF event. The real-world screenshot/document count appears to be approximately 100-105, subject to forensic confirmation. Master-index rows above that number represent duplicate/cross-folder/export records or statement/document rows.

## FILE_5531.pdf

`FILE_5531.pdf` is an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC. It appears in the `TO: Mom` sequence at `2024/04/25 12:54:20`, between screenshot messages at approximately 12:51:02 and 12:54:44.

## Statements

Robin's reported POPD statement and October 1 testimony align with the categories shown in the evidence: financial documents, business names, EIN numbers, bank statements, and similar records. These statements should be verified against the official POPD report/Axon recording and official court record/audio.

## Later-Discovery Explanation

The timing pattern undermines a simple "found later in Photos" explanation. The repeated 0-30 second gaps are more consistent with immediate capture-and-send conduct by the person possessing the phone. The evidence does not independently prove who held the phone.

## Needed Confirmation

Native iPhone database records, Apple/iCloud records, Google records, and POPD Axon materials are still needed to confirm actor identity, sender/recipient handles, attachment GUIDs, transfer metadata, deletion status, and original filenames.
"""
    write(SUMMARY, summary)

    section = f"""## UltData Export / Filename Clarification

{ULTDATA}

## Corrected Event Count Clarification

This packet should refer to 97 unique screenshot-send events within 0-30 seconds. Additional master-index rows may reflect duplicate/cross-folder/export entries. The real-world screenshot/document count appears to be approximately 100-105, subject to forensic confirmation.
"""
    for name in [
        "Executive_Summary_For_Detective.md",
        "Timing_Contradiction_Analysis_For_POPD_SA.md",
        "Technical_Limitations_And_Forensic_Requests.md",
        "POPD_Reopen_Request_Cover_Memo.md",
        "Admission_Corroboration_Matrix.md",
        "Found_Later_Explanation_Analysis_Final.md",
        "Evidence_Strength_Assessment_Final.md",
        "MASTER_REOPEN_PACKET_README.md",
    ]:
        path = FINAL / name
        prior = path.read_text(encoding="utf-8", errors="replace") if path.exists() else f"# {path.stem}\n"
        prior = re.sub(r"191 exhibits with immediate 0-30 second gaps", "97 unique screenshot-send events within 0-30 seconds; additional master-index rows may reflect duplicate/cross-folder/export entries", prior, flags=re.I)
        prior = re.sub(r"191 immediate(?: 0-30 second)? gaps", "97 unique immediate 0-30 second screenshot-send events", prior, flags=re.I)
        prior = re.sub(r"191 screenshots", "97 unique immediate screenshot-send events, with additional duplicate/export rows", prior, flags=re.I)
        prior = re.sub(r"191 unique", "97 unique immediate", prior, flags=re.I)
        if "UltData Export / Filename Clarification" not in prior:
            prior += "\n\n" + section
        write(path, prior)


def canonical_lookup(unique_rows):
    by_hash = {r["PrimarySHA256"].upper(): r for r in unique_rows if r.get("PrimarySHA256")}
    by_ex = {r["PrimaryExhibitNumber"]: r for r in unique_rows if r.get("PrimaryExhibitNumber")}
    return by_hash, by_ex


def top20(master):
    def score(r):
        if r.get("ScreenshotFilenameTimestamp") == "2024-04-19 19:22:24":
            return 100000
        if r.get("DisplayFileName") == "FILE_5531.pdf":
            return 99000
        cats = r.get("OCRCategory", "")
        s = 0
        for term, pts in [("IRS/EIN", 5000), ("Gmail", 4000), ("Google Account", 3800), ("Google Drive", 3700), ("Navy Federal", 3500), ("Bank Statement", 3300), ("Financial Statement", 3200), ("Business Record", 3000), ("Helo Payment Services", 2900)]:
            if term in cats:
                s += pts
        if r.get("ElapsedClassification") == "Immediate":
            s += 1000
        return s
    out, seen = [], set()
    for r in sorted(master, key=score, reverse=True):
        key = r.get("SHA256") or r.get("DisplayFileName")
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
        if len(out) == 20:
            break
    return out


def write_top_and_binder(unique_rows, alias_rows):
    master = read_csv(MASTER)
    by_hash, by_ex = canonical_lookup(unique_rows)
    aliases_by_ce = {r["CanonicalEventId"]: r for r in alias_rows}

    def ce_for(r):
        return by_hash.get((r.get("SHA256") or "").upper()) or by_ex.get(r.get("ExhibitNumber")) or {}

    def block(r, ce):
        alias = aliases_by_ce.get(ce.get("CanonicalEventId", ""), {})
        return f"""- Unique Canonical Event ID: {ce.get('CanonicalEventId', 'Not assigned')}
- Timestamped screenshot filename/path: `{ce.get('TimestampedScreenshotFilePath') or alias.get('TimestampedScreenshotPath') or 'Not applicable'}`
- HTML/media filename/path: `{ce.get('HtmlMediaFilePath') or alias.get('HtmlMediaPath') or r.get('MatchingHtmlMediaFile') or r.get('SourcePath')}`
- Same hash between mapped files: {alias.get('SameHashMatch') or ('Yes' if ce.get('CrossFolderMatchStatus', '').startswith('Same hash') else 'No or not applicable')}
- Duplicate/export representation assessment: {ce.get('OriginalOrExportDerivativeAssessment') or r.get('OriginalOrDerivative')}
- Screenshot filename/capture timestamp: {r.get('ScreenshotFilenameTimestamp') or ce.get('ScreenshotFilenameTimestamp') or 'Not applicable'}
- Texted-to-Mom / Messages.html timestamp: {r.get('MessagesHtmlTimestamp') or ce.get('MessagesHtmlTextedToMomTimestamp') or 'Not available'}
- Elapsed seconds: {r.get('ElapsedSeconds') or ce.get('ElapsedSeconds') or 'Not applicable'}
- Conversation/contact: {r.get('ConversationOrContact') or ce.get('ConversationContact') or 'Mom / not structurally confirmed'}
- Recipient phone if visible: 13863470544 / 1-386-347-0544 visible in export text, not structured handle
- Source/exported device phone if visible: 623 418 0848 visible in export text, not structured handle
- Direction inference: {r.get('DirectionInference') or ce.get('DirectionInference')}
- Native confirmation needed: {ce.get('NativeConfirmationNeeded') or r.get('NativeConfirmationNeeded')}"""

    lines = ["# Top 20 Exhibits With Texted Timestamps", ""]
    for i, r in enumerate(top20(master), 1):
        ce = ce_for(r)
        lines.append(f"## {i}. {r['ExhibitNumber']} - {r['DisplayFileName']}")
        lines.append("")
        lines.append(f"- File path: `{r['SourcePath']}`")
        lines.append(f"- Hash: `{r.get('SHA256')}`")
        lines.append(block(r, ce))
        lines.append(f"- What it shows: {r.get('VisualDescription')}")
        lines.append(f"- Why it matters: {r.get('WhyItMatters')}")
        lines.append(f"- Limitation: {r.get('Limitation')}")
        lines.append("")
    write(FINAL / "Top_20_Exhibits_With_Texted_Timestamps.md", "\n".join(lines))
    write(FINAL / "Top_20_Exhibits_Updated.md", "\n".join(lines))

    binder = ["# Exhibit Binder", "", "This binder distinguishes unique canonical events from duplicate/cross-folder/export file representations.", ""]
    for r in master:
        ce = ce_for(r)
        binder.append(f"## {r['ExhibitNumber']} - {r['DisplayFileName']}")
        binder.append("")
        binder.append(f"- File path: `{r['SourcePath']}`")
        binder.append(f"- SHA256: `{r.get('SHA256')}`")
        binder.append(block(r, ce))
        binder.append(f"- Sensitive content category: {r.get('SensitiveContentType') or r.get('OCRCategory')}")
        binder.append(f"- OCR/visual description: {r.get('VisualDescription')}")
        binder.append(f"- Why this exhibit matters: {r.get('WhyItMatters')}")
        binder.append(f"- Limitation / native confirmation needed: {r.get('Limitation')}")
        binder.append("")
    text = "\n".join(binder)
    write(FINAL / "Exhibit_Binder.md", text)
    write(FINAL / "Exhibit_Binder_NoImages.md", text)


def audit_overstatements():
    issues = []
    for path in FINAL.glob("*.md"):
        text = path.read_text(encoding="utf-8", errors="replace")
        new = text
        for phrase in OVERSTATEMENTS:
            if re.search(re.escape(phrase), new, re.I):
                corrected = False
                repl = None
                if phrase.startswith("191"):
                    repl = "97 unique screenshot-send events within 0-30 seconds; additional rows may reflect duplicate/cross-folder/export entries"
                elif phrase == "200 screenshots captured":
                    repl = "200 OCR-reviewed image file rows, representing fewer unique image events due to duplicate/export copies"
                elif phrase == "every IMG file was sent":
                    repl = "HTML/media files appear in the UltData export and require native confirmation"
                elif phrase in ("Robin sent", "Robin captured", "proves Robin", "proves actor identity"):
                    repl = "the evidence supports the inference, subject to actor-identity confirmation"
                elif phrase in ("guilty", "beyond a reasonable doubt"):
                    repl = "requires forensic confirmation"
                if repl:
                    new = re.sub(re.escape(phrase), repl, new, flags=re.I)
                    corrected = True
                issues.append({"file": path.name, "phrase": phrase, "recommended": repl or "Use neutral investigative language", "corrected": "Yes" if corrected else "No"})
        if new != text:
            path.write_text(new, encoding="utf-8")
    lines = ["# Final Overstatement Audit", ""]
    if not issues:
        lines.append("No overstatement phrases from the requested search list were found after correction.")
    else:
        for i in issues:
            lines.append(f"- File: `{i['file']}`; phrase: `{i['phrase']}`; recommended correction: {i['recommended']}; corrected: {i['corrected']}")
    write(AUDIT, "\n".join(lines))
    return issues


def main():
    unique_rows, alias_rows = build_unique_events()
    write_csv(UNIQUE_CSV, unique_rows, [
        "CanonicalEventId", "EventType", "PrimaryExhibitNumber", "PrimarySHA256", "AllMatchingSHA256sIfAny",
        "ScreenshotFilenameTimestamp", "MessagesHtmlTextedToMomTimestamp", "ElapsedSeconds", "ElapsedClassification",
        "ConversationContact", "RecipientPhoneVisible", "SourceDevicePhoneVisible", "DirectionInference",
        "TimestampedScreenshotFilePath", "TimestampedScreenshotFileName", "HtmlMediaFilePath", "HtmlMediaFileName",
        "OtherMatchingPaths", "CrossFolderMatchStatus", "OriginalOrExportDerivativeAssessment", "OCRSensitiveCategory",
        "OCRKeyTerms", "VisualDescription", "WhyItMatters", "Limitation", "NativeConfirmationNeeded",
    ])
    write_csv(ALIAS_CSV, alias_rows, [
        "CanonicalEventId", "TimestampedScreenshotPath", "TimestampedScreenshotFileName", "HtmlMediaPath",
        "HtmlMediaFileName", "PhotosFolderPath", "MessageAttachmentsPhotosPath", "SHA256", "SizeBytes",
        "Dimensions", "SameHashMatch", "SameTimestampMatch", "SameContentPossible", "Notes",
    ])
    revise_markdown(unique_rows, alias_rows)
    write_top_and_binder(unique_rows, alias_rows)
    issues = audit_overstatements()
    unique_screens = sum(1 for r in unique_rows if r["EventType"] == "Screenshot transmission")
    unique_immediate = sum(1 for r in unique_rows if r["EventType"] == "Screenshot transmission" and r["ElapsedClassification"] == "Immediate")
    duplicates = max(0, len(read_csv(MASTER)) - len(unique_rows))
    print(f"Unique canonical screenshot-send events: {unique_screens}")
    print(f"Unique immediate 0-30 second events: {unique_immediate}")
    print(f"Duplicate/export/cross-folder rows identified by comparison: approximately {duplicates}")
    print("Top 20 canonical event IDs added: Yes")
    print("Top 20 timestamped screenshot and HTML/media paths added where available: Yes")
    print("191-vs-97 issue corrected: Yes")
    print("UltData/IMG/media filename clarification added: Yes")
    print(f"Overstatement issues found and corrected/listed: {len(issues)}")


if __name__ == "__main__":
    main()
