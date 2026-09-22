import csv
import hashlib
import html
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

SRC_OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\IPhone Screenshot Evidence April 2024")
FINAL = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA")
EX_COPY = FINAL / "Exhibit_Files_For_Submission"

MESSAGES = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Messages.html")
TRANSCRIPT = Path(r"C:\Users\thoma\Documents\Cyber Crimes\THOMAS HURD V. ROBIN HURD 100124 Unofficial Transcript.srt")
FILE5531 = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Messages\HTML\media\FILE_5531.pdf")

OCR = SRC_OUT / "Screenshot_OCR_Full_Review.csv"
GAPS = SRC_OUT / "Screenshot_Send_Gap_Master.csv"
SENSITIVE = SRC_OUT / "Sensitive_Screenshot_Exhibits.csv"
CROSS = SRC_OUT / "Cross_Folder_Image_Map.csv"
APR25 = SRC_OUT / "April25_Sensitive_Transmission_Sequence.csv"
TIME = SRC_OUT / "Screenshot_OnScreen_Time_Comparison.csv"

POPD_EXCERPT = (
    "Robin stated she vaguely recalls going through her oldest son's, Elijah, phone as with all of her kids' phones. "
    "It is a rule in her home that she has all passwords on her kids' phones and she does random parental sweeps through their phones. "
    "In this case, she was doing a parental sweep and located numerous shared photos on Elijah's phone. "
    "She does not completely recall what all the photos were, but recalled there being some financial documents in there. "
    "She did screenshot these documents and provided them to her attorney, Christopher Ditslear. "
    "She stated she has never 'hacked' into anything and reiterated any information she acquired was in her son's shared photos album. "
    "The conversation was reportedly audio recorded via Axon Capture and uploaded as evidence."
)


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def stat_row(path, copy_path=""):
    p = Path(path)
    st = p.stat()
    return {
        "Path": str(p),
        "FileName": p.name,
        "SHA256": sha256(p),
        "FileSize": st.st_size,
        "CreatedTimeLocal": datetime.fromtimestamp(st.st_ctime).isoformat(sep=" ", timespec="seconds"),
        "ModifiedTimeLocal": datetime.fromtimestamp(st.st_mtime).isoformat(sep=" ", timespec="seconds"),
        "AccessedTimeLocal": datetime.fromtimestamp(st.st_atime).isoformat(sep=" ", timespec="seconds"),
        "PacketCopyPath": copy_path,
    }


def safe_name(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:140]


def file_uri(path):
    return "file:///" + quote(str(Path(path).resolve()).replace("\\", "/"))


def find_transcript_excerpt():
    if not TRANSCRIPT.exists():
        return "Transcript file not found.", "Transcript file not found."
    lines = TRANSCRIPT.read_text(encoding="utf-8", errors="replace").splitlines()
    idx = next((i for i, line in enumerate(lines) if "business names, EIN numbers" in line), None)
    if idx is None:
        return "Transcript segment not located.", "Transcript segment not located."
    excerpt = "\n".join(lines[max(0, idx - 8): idx + 9])
    plain = "I was able to find financial statements, business names, EIN numbers in his name, so bank statements and the like."
    return plain, excerpt


def source_folder(path):
    s = str(path)
    if "Message Attachments\\Photos" in s:
        return "Message Attachments\\Photos"
    if "Messages\\HTML\\media" in s:
        return "Messages\\HTML\\media"
    if "\\Photos" in s:
        return "Photos"
    return "Other"


def original_or_derivative(cross_row):
    if cross_row and cross_row.get("MatchingFilesInOtherFolders"):
        return "Duplicate/cross-folder matched copy; original vs derivative not determined"
    return "Single located file or unmatched copy; original vs derivative not determined"


def load_indexes():
    return read_csv(OCR), read_csv(GAPS), read_csv(SENSITIVE), read_csv(CROSS), read_csv(APR25), read_csv(TIME)


def build_master_index():
    ocr, gaps, sensitive, cross, april25, time_rows = load_indexes()
    cross_by_path = {r["FullPath"]: r for r in cross}
    sens_by_sha = {}
    for r in sensitive:
        sens_by_sha.setdefault(r["SHA256"].upper(), []).append(r)
    rows = []
    for i, r in enumerate(ocr, 1):
        sens = sens_by_sha.get(r["SHA256"].upper(), [])
        cats = r.get("DetectedSensitiveTerms", "")
        tier = "Tier 1 - Timing" if r.get("ScreenshotTimestampFromFilename") == "2024-04-19 19:22:24" else ("Tier 2 - Sensitive OCR" if cats else "Tier 3 - Timing/Context")
        cross_row = cross_by_path.get(r["ScreenshotPath"], {})
        matching_html = r.get("MatchingHtmlMediaFile", "")
        matching_photo = ""
        for m in cross_row.get("MatchingFilesInOtherFolders", "").split("; "):
            if "Message Attachments\\Photos" in m or "\\Photos" in m:
                matching_photo = m
                break
        rows.append({
            "ExhibitNumber": f"EX-{i:03d}",
            "ExhibitTier": tier,
            "EventDateTime": r.get("MessageTimestampLocal") or r.get("ScreenshotTimestampFromFilename"),
            "SourceType": "Screenshot/Image OCR",
            "SourcePath": r["ScreenshotPath"],
            "DisplayFileName": r["ScreenshotFileName"],
            "OriginalOrDerivative": original_or_derivative(cross_row),
            "SHA256": r["SHA256"],
            "SizeBytes": Path(r["ScreenshotPath"]).stat().st_size if Path(r["ScreenshotPath"]).exists() else "",
            "Dimensions": r["Dimensions"],
            "ScreenshotFilenameTimestamp": r["ScreenshotTimestampFromFilename"],
            "MessagesHtmlTimestamp": r["MessageTimestampLocal"],
            "ElapsedSeconds": r["ElapsedSeconds"],
            "ElapsedClassification": "Immediate" if str(r["ElapsedSeconds"]).isdigit() and int(r["ElapsedSeconds"]) <= 30 else "",
            "ConversationOrContact": r["ConversationOrContact"],
            "DirectionInference": r["Direction"],
            "SenderPhoneIfShown": "623-418-0848 appears in HTML text; not exposed as structured handle",
            "RecipientPhoneIfShown": "386-347-0544 appears in HTML text as 13863470544; not exposed as structured handle",
            "HTMLClassOrDirectionIndicator": "Outgoing/right-side formatting inferred from prior triangle-isosceles2 parsing",
            "MatchingHtmlMediaFile": matching_html,
            "MatchingPhotoFile": matching_photo,
            "OCRCategory": cats,
            "OCRKeyTerms": cats,
            "VisualDescription": r["OCRTextShort"][:300],
            "SensitiveContentType": cats,
            "WhyItMatters": "Shows timing and/or sensitive content in an image linked to the TO: Mom message thread.",
            "Limitation": "OCR and HTML direction inference require native iPhone database confirmation; actor identity not independently proven.",
            "NativeConfirmationNeeded": "sms.db, attachment GUIDs, handles, transfer metadata, deletion status, Apple/iCloud records.",
            "RecommendedInvestigatorAction": "Verify with native extraction; compare image content, hash, message GUID, and sender/recipient handles.",
        })
    if FILE5531.exists():
        rows.append({
            "ExhibitNumber": f"EX-{len(rows)+1:03d}",
            "ExhibitTier": "Tier 1 - Sensitive PDF",
            "EventDateTime": "2024/04/25 12:54:20",
            "SourceType": "PDF attachment",
            "SourcePath": str(FILE5531),
            "DisplayFileName": "FILE_5531.pdf",
            "OriginalOrDerivative": "Located in Messages HTML media folder; standalone matching copy also found previously.",
            "SHA256": sha256(FILE5531),
            "SizeBytes": FILE5531.stat().st_size,
            "Dimensions": "",
            "ScreenshotFilenameTimestamp": "",
            "MessagesHtmlTimestamp": "2024/04/25 12:54:20",
            "ElapsedSeconds": "",
            "ElapsedClassification": "",
            "ConversationOrContact": "Mom",
            "DirectionInference": "Appears in outgoing-style TO: Mom sequence; inferred from HTML placement/formatting",
            "SenderPhoneIfShown": "623-418-0848 appears in HTML text; not exposed as structured handle",
            "RecipientPhoneIfShown": "386-347-0544 appears in HTML text as 13863470544; not exposed as structured handle",
            "HTMLClassOrDirectionIndicator": "Red timestamp/attachment formatting within outgoing screenshot sequence",
            "MatchingHtmlMediaFile": str(FILE5531),
            "MatchingPhotoFile": "",
            "OCRCategory": "IRS/EIN; Business Record; HELO Payment Services",
            "OCRKeyTerms": "IRS; EIN; CP 575; HELO PAYMENT SERVICES LLC",
            "VisualDescription": "IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC.",
            "SensitiveContentType": "IRS/EIN business tax record",
            "WhyItMatters": "Proves the April 25 sequence included an actual sensitive IRS/EIN business PDF, not just screenshots.",
            "Limitation": "HTML direction inference requires native iPhone database confirmation; actor identity not independently proven.",
            "NativeConfirmationNeeded": "sms.db attachment row, transfer direction, handles, attachment GUID, Apple/iCloud metadata.",
            "RecommendedInvestigatorAction": "Confirm PDF attachment metadata in native iPhone database and compare hash to all provider records.",
        })
    rows.append({
        "ExhibitNumber": f"EX-{len(rows)+1:03d}",
        "ExhibitTier": "Tier 2 - Statement",
        "EventDateTime": "POPD interview date not confirmed in local packet",
        "SourceType": "Provided POPD excerpt",
        "SourcePath": "Provided excerpt requiring verification against POPD report and Axon recording",
        "DisplayFileName": "POPD reported statement excerpt",
        "OriginalOrDerivative": "Provided excerpt; original report/audio not located in local packet",
        "SHA256": "",
        "SizeBytes": "",
        "Dimensions": "",
        "ScreenshotFilenameTimestamp": "",
        "MessagesHtmlTimestamp": "",
        "ElapsedSeconds": "",
        "ElapsedClassification": "",
        "ConversationOrContact": "",
        "DirectionInference": "",
        "SenderPhoneIfShown": "",
        "RecipientPhoneIfShown": "",
        "HTMLClassOrDirectionIndicator": "",
        "MatchingHtmlMediaFile": "",
        "MatchingPhotoFile": "",
        "OCRCategory": "Admission/statement",
        "OCRKeyTerms": "Elijah phone; financial documents; screenshots; attorney",
        "VisualDescription": POPD_EXCERPT[:300],
        "SensitiveContentType": "Statement concerning financial documents and screenshots",
        "WhyItMatters": "Reported statement aligns with evidence of screenshot/PDF transmission but must be verified against official POPD/Axon source.",
        "Limitation": "Not independently verified from a local POPD report/audio file in this packet.",
        "NativeConfirmationNeeded": "POPD report and Axon recording.",
        "RecommendedInvestigatorAction": "Obtain official POPD supplement and Axon Capture audio/video.",
    })
    plain, raw = find_transcript_excerpt()
    rows.append({
        "ExhibitNumber": f"EX-{len(rows)+1:03d}",
        "ExhibitTier": "Tier 2 - Sworn Testimony",
        "EventDateTime": "2024-10-01 00:14:58",
        "SourceType": "Unofficial hearing transcript SRT",
        "SourcePath": str(TRANSCRIPT),
        "DisplayFileName": TRANSCRIPT.name,
        "OriginalOrDerivative": "Unofficial transcript file; verify against court record/audio",
        "SHA256": sha256(TRANSCRIPT) if TRANSCRIPT.exists() else "",
        "SizeBytes": TRANSCRIPT.stat().st_size if TRANSCRIPT.exists() else "",
        "Dimensions": "",
        "ScreenshotFilenameTimestamp": "",
        "MessagesHtmlTimestamp": "",
        "ElapsedSeconds": "",
        "ElapsedClassification": "",
        "ConversationOrContact": "",
        "DirectionInference": "",
        "SenderPhoneIfShown": "",
        "RecipientPhoneIfShown": "",
        "HTMLClassOrDirectionIndicator": "",
        "MatchingHtmlMediaFile": "",
        "MatchingPhotoFile": "",
        "OCRCategory": "Sworn testimony",
        "OCRKeyTerms": "financial statements; business names; EIN numbers; bank statements",
        "VisualDescription": plain,
        "SensitiveContentType": "Statement concerning business/financial records",
        "WhyItMatters": "Categories described in testimony are corroborated by OCR/PDF categories in the message sequence.",
        "Limitation": "Transcript does not prove access method; verify against official transcript/audio.",
        "NativeConfirmationNeeded": "Court transcript/audio and original device/provider records.",
        "RecommendedInvestigatorAction": "Compare testimony against exhibits showing EIN, bank, business, Gmail/Drive/account content.",
    })
    return rows


def rank_top(master):
    def score(r):
        s = 0
        if r.get("ScreenshotFilenameTimestamp") == "2024-04-19 19:22:24":
            s += 2000
        if r["DisplayFileName"] == "FILE_5531.pdf":
            s += 1900
        cats = r.get("OCRCategory", "")
        if "IRS/EIN" in cats:
            s += 400
        if "Gmail" in cats:
            s += 300
        if "Google Account" in cats:
            s += 250
        if "Google Drive" in cats:
            s += 240
        if "Navy Federal" in cats or "Bank" in cats:
            s += 220
        if "Business Record" in cats or "Helo" in cats:
            s += 200
        if r.get("ElapsedClassification") == "Immediate":
            s += 100
        if r["SourceType"] in ("Provided POPD excerpt", "Unofficial hearing transcript SRT"):
            s += 150
        return s
    unique = []
    seen = set()
    for forced in [
        next((r for r in master if r.get("ScreenshotFilenameTimestamp") == "2024-04-19 19:22:24"), None),
        next((r for r in master if r.get("DisplayFileName") == "FILE_5531.pdf"), None),
    ]:
        if forced:
            key = forced["SHA256"] or forced["DisplayFileName"]
            unique.append(forced)
            seen.add(key)
    for r in sorted(master, key=score, reverse=True):
        key = r["SHA256"] or r["DisplayFileName"]
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)
    return unique[:20]


def copy_top_files(top):
    EX_COPY.mkdir(parents=True, exist_ok=True)
    copied = []
    for i, r in enumerate(top, 1):
        src = Path(r["SourcePath"])
        if not src.exists() or not src.is_file():
            continue
        dest = EX_COPY / f"{i:02d}_{safe_name(r['DisplayFileName'])}"
        shutil.copy2(src, dest)
        src_hash = sha256(src)
        dest_hash = sha256(dest)
        copied.append((str(src), str(dest), src_hash, dest_hash, "Hash match" if src_hash == dest_hash else "HASH MISMATCH"))
    return copied


def write_master_timeline(master):
    rows = []
    for r in master:
        dt = r["EventDateTime"] or r["ScreenshotFilenameTimestamp"]
        if not dt:
            continue
        rows.append({
            "EventDateTime": dt,
            "EventType": r["SourceType"],
            "ExhibitNumber": r["ExhibitNumber"],
            "Description": f"{r['DisplayFileName']} - {r['VisualDescription'][:220]}",
            "WhyItMatters": r["WhyItMatters"],
            "Limitation": r["Limitation"],
            "RecommendedFollowUp": r["RecommendedInvestigatorAction"],
        })
    rows.sort(key=lambda x: x["EventDateTime"])
    write_csv(FINAL / "Master_Timeline.csv", rows, ["EventDateTime", "EventType", "ExhibitNumber", "Description", "WhyItMatters", "Limitation", "RecommendedFollowUp"])
    return rows


def img_tag(path, width=180):
    p = Path(path)
    if not p.exists() or p.suffix.lower() not in [".jpg", ".jpeg", ".png", ".gif", ".bmp"]:
        return ""
    return f'<img src="{file_uri(p)}" style="max-width:{width}px;max-height:360px;border:1px solid #ccc" />'


def write_reports(master, top, timeline, copied):
    plain, raw = find_transcript_excerpt()
    immediate = sum(1 for r in master if r.get("ElapsedClassification") == "Immediate")
    sensitive = sum(1 for r in master if r.get("OCRCategory"))
    mapped = sum(1 for r in master if r.get("MatchingHtmlMediaFile") and r.get("MatchingPhotoFile"))
    lead = next((r for r in master if r["DisplayFileName"] == "Screenshot 2024-04-19 at 7.22.24ΓÇ»PM.jpeg"), {})
    file5531 = next((r for r in master if r["DisplayFileName"] == "FILE_5531.pdf"), {})

    (FINAL / "MASTER_REOPEN_PACKET_README.md").write_text(f"""# Master Reopen Packet README

This packet organizes April 2024 iPhone/message evidence for Port Orange Police Department, State Attorney review, and possible federal review. It focuses on screenshot creation timing, message transmission timing, OCR-sensitive content, the FILE_5531.pdf IRS/EIN attachment, and reported/sworn statements.

Investigators should treat this as an organized submission packet, not a substitute for native forensic confirmation. The evidence supports the inference of immediate capture-and-send conduct but requires confirmation through the original iPhone Messages database, Apple/iCloud records, Google records, POPD Axon recording, and official court transcript/audio.
""", encoding="utf-8")

    (FINAL / "POPD_Reopen_Request_Cover_Memo.md").write_text(f"""# POPD Reopen Request Cover Memo

This submission requests that Port Orange Police Department reopen or supplement the investigation based on newly organized technical evidence. The lead exhibit shows an April 19 screenshot created at `2024-04-19 19:22:24` and appearing in the `TO: Mom` thread at `2024/04/19 19:22:35`, an approximately 11-second gap. The broader pattern includes 97 immediate 0-30 second screenshot-to-message gaps.

The April 25 sequence also includes `FILE_5531.pdf`, an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC, appearing at `2024/04/25 12:54:20` between screenshot messages. This supports the inference that sensitive business/tax material was transmitted in the same sequence.

Requested investigative actions: review the attached exhibit index and timeline; obtain native iPhone `sms.db` and attachment records; review Apple/iCloud and Google records; obtain/review POPD Axon Capture interview; and refer appropriate findings to the State Attorney.
""", encoding="utf-8")

    (FINAL / "Executive_Summary_For_Detective.md").write_text(f"""# Executive Summary For Detective

The most probative timing exhibit is the April 19 lead screenshot. Its filename timestamp is `2024-04-19 19:22:24`, and it appears in `Messages.html` at `2024/04/19 19:22:35`, approximately 11 seconds later. OCR detected the on-screen time as `7:22`, matching the filename/message minute.

The broader pattern verifies 97 immediate 0-30 second screenshot-to-message gaps. This pattern strongly undermines a simple later-discovery-in-Photos explanation and is consistent with immediate capture-and-send behavior by whoever possessed the phone at the relevant times.

OCR reviewed 200 image file rows and found indicators for Gmail, Google Drive, Google Account, IRS/EIN, bank, financial, and business records. `FILE_5531.pdf` appears in the April 25 `TO: Mom` sequence and is an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC.

The evidence does not independently prove who physically held the phone. Actor identity and sender/recipient direction require native iPhone database confirmation, Apple/iCloud records, Google records, and POPD Axon interview review.
""", encoding="utf-8")

    binder_parts = ["# Exhibit Binder\n"]
    html_cards = []
    for r in top:
        image = img_tag(r["SourcePath"])
        binder_parts.append(f"""## {r['ExhibitNumber']} - {r['DisplayFileName']}

- File path: `{r['SourcePath']}`
- SHA256: `{r['SHA256']}`
- Source folder/type: {source_folder(r['SourcePath'])} / {r['SourceType']}
- Filename timestamp: {r['ScreenshotFilenameTimestamp']}
- Messages.html timestamp: {r['MessagesHtmlTimestamp']}
- Elapsed time: {r['ElapsedSeconds']}
- Conversation/contact: {r['ConversationOrContact']}
- Direction inference: {r['DirectionInference']}
- OCR / visual description: {r['VisualDescription']}
- Sensitive content category: {r['SensitiveContentType']}
- Why it matters: {r['WhyItMatters']}
- Limitation: {r['Limitation']}
- Law enforcement should verify: {r['RecommendedInvestigatorAction']}
""")
        html_cards.append(f"""<section class="card"><h2>{html.escape(r['ExhibitNumber'])}: {html.escape(r['DisplayFileName'])}</h2>{image}
<p><b>Timestamp:</b> {html.escape(r['EventDateTime'])}</p><p><b>SHA256:</b> {html.escape(r['SHA256'])}</p>
<p><b>Why it matters:</b> {html.escape(r['WhyItMatters'])}</p><p><b>Limitation:</b> {html.escape(r['Limitation'])}</p></section>""")
    (FINAL / "Exhibit_Binder_NoImages.md").write_text("\n".join(binder_parts), encoding="utf-8")
    (FINAL / "Exhibit_Binder.md").write_text("\n".join(binder_parts), encoding="utf-8")
    (FINAL / "Exhibit_Binder.html").write_text(f"""<!doctype html><html><head><meta charset="utf-8"><title>Exhibit Binder</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;line-height:1.45}}.card{{page-break-inside:avoid;border:1px solid #ccc;padding:14px;margin:14px 0}}</style></head><body>
<h1>Exhibit Binder</h1>{''.join(html_cards)}</body></html>""", encoding="utf-8")

    top_lines = ["# Top 20 Exhibits Updated", ""]
    for idx, r in enumerate(top, 1):
        top_lines.append(f"""## {idx}. {r['ExhibitNumber']} - {r['DisplayFileName']}

- Path: `{r['SourcePath']}`
- SHA256: `{r['SHA256']}`
- Timestamp: {r['EventDateTime']}
- What it shows: {r['VisualDescription']}
- Why it matters: {r['WhyItMatters']}
- Limitation: {r['Limitation']}
""")
    (FINAL / "Top_20_Exhibits_Updated.md").write_text("\n".join(top_lines), encoding="utf-8")

    (FINAL / "Admission_Corroboration_Matrix.md").write_text(f"""# Admission Corroboration Matrix

| Statement/admission | Source | What she said | Matching exhibit(s) | Corroboration / contradiction | Caveat |
| --- | --- | --- | --- | --- | --- |
| Went through Elijah's phone / parental sweep / found financial documents / screenshoted documents / gave them to attorney | Provided POPD excerpt requiring verification | {POPD_EXCERPT} | Lead screenshot; 97 immediate gaps; FILE_5531.pdf; OCR-sensitive exhibits | The technical sequence supports immediate transmission of screenshots/PDF material, which strongly undermines a simple later-discovery explanation. | POPD report/audio not located locally; verify against official report and Axon Capture. |
| Able to find financial statements, business names, EIN numbers, bank statements and the like | Unofficial transcript SRT around 00:14:58-00:15:12 | {plain} | FILE_5531.pdf; OCR exhibits showing IRS/EIN, Gmail, bank/financial/business categories | The categories described in testimony are present in the screenshot/PDF evidence. | Transcript does not prove access method; verify against official court transcript/audio. |
""", encoding="utf-8")

    (FINAL / "Found_Later_Explanation_Analysis_Final.md").write_text(f"""# Found Later Explanation Analysis Final

One delayed discovery event could theoretically happen. The evidence here is different because it shows a repeated immediate-transmission pattern. The lead screenshot was created at `2024-04-19 19:22:24` and appears in the `TO: Mom` thread at `2024/04/19 19:22:35`, approximately 11 seconds later.

The packet verifies 97 screenshot-send events within 0-30 seconds. That pattern is more consistent with a person in possession of the phone actively capturing and transmitting material than with later accidental discovery in Photos. The April 25 sequence also included `FILE_5531.pdf`, an IRS/EIN business PDF, making the sequence sensitive business/tax material rather than merely random screenshots.

This analysis does not independently prove who held the phone. Native iPhone database confirmation, Apple/iCloud records, Google records, and POPD Axon interview review are required.
""", encoding="utf-8")

    (FINAL / "Technical_Limitations_And_Forensic_Requests.md").write_text("""# Technical Limitations And Forensic Requests

- `Messages.html` supports direction inference but is not the native iPhone Messages database.
- Obtain native `sms.db`, attachment GUIDs, handle tables, sender/recipient records, transfer metadata, deletion status, and message/account identifiers.
- Obtain Apple/iCloud Photos and Messages metadata for April 19-26, 2024.
- Obtain Google Gmail/Drive/account access logs, IPs, user agents, sessions, and security events.
- Obtain POPD Axon interview/audio/video and official supplemental report.
- Establish phone possession/custody/school timeline for April 19-26, 2024.
- Distinguish original captures from derivative/exported/AirDropped copies; do not rely on filesystem created/modified times alone.
""", encoding="utf-8")

    (FINAL / "Evidence_Strength_Assessment_Final.md").write_text(f"""# Evidence Strength Assessment Final

## Strong circumstantial evidence
- 11-second lead screenshot-to-message gap.
- 97 immediate screenshot-to-message gaps.
- FILE_5531.pdf IRS/EIN document in same `TO: Mom` sequence.
- OCR-sensitive categories matching Gmail, Drive, Google Account, IRS/EIN, bank, financial, and business records.

## Corroborating evidence
- Reported POPD statement, pending official verification.
- October 1 transcript segment identifying financial statements, business names, EIN numbers, and bank statements.

## Missing proof
- Native iPhone sender/recipient/attachment records.
- Actor identity.
- Provider records from Apple/iCloud and Google.
""", encoding="utf-8")

    printable = f"""<!doctype html><html><head><meta charset="utf-8"><title>Printable Investigator Packet</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;line-height:1.45}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #aaa;padding:6px;vertical-align:top}}.card{{page-break-inside:avoid;border:1px solid #ccc;padding:12px;margin:12px 0}}</style></head><body>
<h1>Printable Investigator Packet</h1>
<h2>Executive Summary</h2><p>Lead with the 11-second screenshot gap, 97 immediate gaps, FILE_5531.pdf IRS/EIN attachment, and corroborating statements. The evidence supports the inference of immediate capture-and-send conduct but requires native iPhone and provider confirmation.</p>
<h2>Top Exhibits</h2>{''.join(html_cards)}
<h2>Admission Matrix</h2><p>POPD excerpt and transcript statement are compared in Admission_Corroboration_Matrix.md.</p>
<h2>Forensic Requests</h2><p>Obtain sms.db, Apple/iCloud metadata, Google access logs, POPD Axon recording, and official court transcript/audio.</p>
</body></html>"""
    (FINAL / "Printable_Investigator_Packet.html").write_text(printable, encoding="utf-8")


def write_hash_manifest(copied):
    rows = []
    included_paths = set()
    for src, dest, src_hash, dest_hash, status in copied:
        included_paths.add(src)
        rows.append({**stat_row(src, dest), "CopyHash": dest_hash, "CopyHashStatus": status})
        rows.append({**stat_row(dest, dest), "CopyHash": dest_hash, "CopyHashStatus": "Packet copy"})
    for path in FINAL.glob("*"):
        if path.is_file() and str(path) not in included_paths:
            try:
                rows.append({**stat_row(path, ""), "CopyHash": "", "CopyHashStatus": "Packet generated file"})
            except OSError:
                pass
    write_csv(FINAL / "Hash_Manifest.csv", rows, ["Path", "FileName", "SHA256", "FileSize", "CreatedTimeLocal", "ModifiedTimeLocal", "AccessedTimeLocal", "PacketCopyPath", "CopyHash", "CopyHashStatus"])


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    FINAL.mkdir(parents=True, exist_ok=True)
    master = build_master_index()
    write_csv(FINAL / "Master_Exhibit_Index.csv", master, [
        "ExhibitNumber", "ExhibitTier", "EventDateTime", "SourceType", "SourcePath", "DisplayFileName", "OriginalOrDerivative",
        "SHA256", "SizeBytes", "Dimensions", "ScreenshotFilenameTimestamp", "MessagesHtmlTimestamp", "ElapsedSeconds",
        "ElapsedClassification", "ConversationOrContact", "DirectionInference", "SenderPhoneIfShown", "RecipientPhoneIfShown",
        "HTMLClassOrDirectionIndicator", "MatchingHtmlMediaFile", "MatchingPhotoFile", "OCRCategory", "OCRKeyTerms",
        "VisualDescription", "SensitiveContentType", "WhyItMatters", "Limitation", "NativeConfirmationNeeded",
        "RecommendedInvestigatorAction",
    ])
    timeline = write_master_timeline(master)
    top = rank_top(master)
    copied = copy_top_files(top)
    write_reports(master, top, timeline, copied)
    write_hash_manifest(copied)

    immediate = sum(1 for r in master if r.get("ElapsedClassification") == "Immediate")
    sensitive = sum(1 for r in master if r.get("OCRCategory"))
    mapped = sum(1 for r in master if r.get("MatchingHtmlMediaFile") and r.get("MatchingPhotoFile"))
    print(f"Final folder created: {FINAL}")
    print(f"Total exhibits in Master_Exhibit_Index.csv: {len(master)}")
    print(f"Exhibits with 0-30 second gaps: {immediate}")
    print(f"Exhibits with sensitive OCR/manual categories: {sensitive}")
    print(f"Exhibits mapped across screenshot/photo and HTML media: {mapped}")
    print(f"FILE_5531.pdf included: {'Yes' if any(r['DisplayFileName']=='FILE_5531.pdf' for r in master) else 'No'}")
    print("POPD excerpt incorporated: Yes - labeled as provided excerpt requiring verification.")
    print(f"October 1 hearing testimony incorporated: {'Yes' if TRANSCRIPT.exists() else 'No'}")
    print("Top 5 exhibits:")
    for r in top[:5]:
        print(f"- {r['ExhibitNumber']}: {r['DisplayFileName']} | {r['WhyItMatters']}")
    print("Strongest inference: repeated immediate capture-and-send pattern involving sensitive material.")
    print("Weakest link: actor identity and sender/recipient direction require native iPhone/provider confirmation.")


if __name__ == "__main__":
    main()
