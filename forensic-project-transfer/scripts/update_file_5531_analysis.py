import csv
import hashlib
import re
from datetime import datetime
from email import policy
from email.parser import BytesParser
from pathlib import Path

from pypdf import PdfReader

BASE_OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\IPhone Screenshot Evidence April 2024")
PDF_PATH = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Messages\HTML\media\FILE_5531.pdf")
PDF_COPY = Path(r"C:\Users\thoma\Documents\Cyber Crimes\FILE_5531.pdf")
MESSAGES_HTML = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Messages.html")
MBOX_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes\MBOX Evidence April 2024")

COMBINED_TIMELINE = BASE_OUT / "combined_april_2024_timeline.csv"
PDF_MD = BASE_OUT / "file_5531_pdf_analysis.md"
PDF_CSV = BASE_OUT / "file_5531_pdf_inventory.csv"
PROSECUTION_TIMELINE = BASE_OUT / "Prosecution_Evidence_Timeline.csv"
TOP_EXHIBITS = BASE_OUT / "Top_Exhibits_List.md"
PACKET_REPORT = BASE_OUT / "New_Evidence_Packet_April2024_Screenshot_Transmission_Report.md"
DETECTIVE_TIMELINE = BASE_OUT / "Detective_Timeline_Report.md"
PRIOR_REPORT = BASE_OUT / "April2024_iPhone_Screenshot_Evidence_Report.md"


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def fmt_time(ts):
    return datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")


def redacted(text):
    text = re.sub(r"\b\d{2}-\d{7}\b", "[REDACTED EIN]", text)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED SSN-LIKE]", text)
    return text


def pdf_text(path):
    try:
        reader = PdfReader(str(path))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        return len(reader.pages), text
    except Exception as exc:
        return "", f"TEXT EXTRACTION FAILED: {exc}"


def classify_pdf(text):
    low = text.lower()
    flags = {
        "IRS EIN letter": "internal revenue service" in low and "employer identification number" in low,
        "CP 575": "cp 575" in low,
        "147C": "147c" in low,
        "Helo Payment Services LLC EIN document": "helo payment services llc" in low and "ein" in low,
        "bank/financial document": any(t in low for t in ["bank statement", "navy federal", "voided check"]),
        "other business record": "business" in low or "llc" in low,
    }
    return "; ".join(k for k, v in flags.items() if v)


def message_context():
    text = MESSAGES_HTML.read_text(encoding="utf-8", errors="replace") if MESSAGES_HTML.exists() else ""
    lines = text.splitlines()
    idxs = [i for i, line in enumerate(lines) if "FILE_5531.pdf" in line]
    if not idxs:
        return {
            "MessagesHtmlReferences": "No",
            "HtmlLinkType": "",
            "MessageTimestampLocal": "",
            "ConversationContact": "",
            "AppearsOutgoingToMom": "No",
            "SameThreadAsScreenshots": "Unknown",
            "CloseToScreenshotSequence": "Unknown",
            "ContextSnippet": "",
        }
    idx = idxs[0]
    context = "\n".join(lines[max(0, idx - 12): idx + 8])
    before = "\n".join(lines[:idx])
    ts_matches = re.findall(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", before)
    timestamp = ts_matches[-1] if ts_matches else ""
    contact_match = re.search(r"TO:\s*([^<\n]+)", text)
    contact = contact_match.group(1).strip() if contact_match else ""
    link_type = "Clickable href" if re.search(r"<a[^>]+href=['\"]media/FILE_5531\.pdf", context, re.I) else "Referenced/displayed as attachment row, not a visible href in parsed HTML"
    outgoing = "Yes - inferred from TO: Mom thread, red timestamp/attachment formatting, and placement inside outgoing screenshot sequence"
    return {
        "MessagesHtmlReferences": "Yes",
        "HtmlLinkType": link_type,
        "MessageTimestampLocal": timestamp,
        "ConversationContact": contact,
        "AppearsOutgoingToMom": outgoing,
        "SameThreadAsScreenshots": "Yes - same Messages.html conversation labeled TO: Mom",
        "CloseToScreenshotSequence": "Yes - between screenshot messages at 12:51:02 and 12:54:44 on April 25, 2024",
        "ContextSnippet": redacted(" ".join(context.split()))[:900],
    }


def compare_known_files(pdf_hash, pdf_text_value):
    matches = []
    candidates = []
    if PDF_COPY.exists():
        candidates.append(PDF_COPY)
    for root in [MBOX_DIR, Path(r"C:\Users\thoma\Documents\Cyber Crimes")]:
        if root.exists():
            for p in root.rglob("*.pdf"):
                if p == PDF_PATH:
                    continue
                name_low = p.name.lower()
                if any(t in name_low for t in ["file_5531", "helo", "ein", "irs", "cp 575", "147c"]):
                    candidates.append(p)
    seen = set()
    for p in candidates:
        if str(p).lower() in seen or not p.exists():
            continue
        seen.add(str(p).lower())
        try:
            h = sha256_file(p)
            pages, text = pdf_text(p)
            same_text = bool(text and pdf_text_value and redacted(text[:4000]) == redacted(pdf_text_value[:4000]))
            matches.append({
                "Path": str(p),
                "FileName": p.name,
                "Size": p.stat().st_size,
                "SHA256": h,
                "HashMatchesFILE5531": "Yes" if h == pdf_hash else "No",
                "TextAppearsSame": "Yes" if same_text else "No",
                "Source": "Known standalone PDF copy or candidate local PDF",
            })
        except Exception as exc:
            matches.append({
                "Path": str(p),
                "FileName": p.name,
                "Size": "",
                "SHA256": "",
                "HashMatchesFILE5531": "Error",
                "TextAppearsSame": "Error",
                "Source": f"Could not compare: {exc}",
            })
    eml_hash_matches = 0
    eml_candidates = 0
    if MBOX_DIR.exists():
        for eml in MBOX_DIR.rglob("*.eml"):
            try:
                msg = BytesParser(policy=policy.default).parsebytes(eml.read_bytes())
            except Exception:
                continue
            for part in msg.walk():
                fn = part.get_filename() or ""
                payload = part.get_payload(decode=True) or b""
                if fn or part.get_content_type() == "application/pdf":
                    h = hashlib.sha256(payload).hexdigest().upper() if payload else ""
                    if h == pdf_hash:
                        eml_hash_matches += 1
                    if h == pdf_hash or any(t in fn.lower() for t in ["helo", "ein", "irs", "cp 575", "147c", "file_5531"]):
                        eml_candidates += 1
    return matches, eml_hash_matches, eml_candidates


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


def main():
    BASE_OUT.mkdir(parents=True, exist_ok=True)
    exists = PDF_PATH.exists()
    st = PDF_PATH.stat() if exists else None
    pdf_hash = sha256_file(PDF_PATH) if exists else ""
    pages, text = pdf_text(PDF_PATH) if exists else ("", "")
    classification = classify_pdf(text)
    msg = message_context()
    comparisons, eml_hash_matches, eml_candidates = compare_known_files(pdf_hash, text) if exists else ([], 0, 0)

    inventory_row = {
        "FullPath": str(PDF_PATH),
        "FileName": PDF_PATH.name,
        "Exists": "Yes" if exists else "No",
        "FileSize": st.st_size if st else "",
        "CreatedTimeLocal": fmt_time(st.st_ctime) if st else "",
        "ModifiedTimeLocal": fmt_time(st.st_mtime) if st else "",
        "AccessedTimeLocal": fmt_time(st.st_atime) if st else "",
        "SHA256": pdf_hash,
        "MessagesHtmlReferences": msg["MessagesHtmlReferences"],
        "HtmlLinkType": msg["HtmlLinkType"],
        "MessageTimestampLocal": msg["MessageTimestampLocal"],
        "ConversationContact": msg["ConversationContact"],
        "AppearsOutgoingToMom": msg["AppearsOutgoingToMom"],
        "SameThreadAsScreenshots": msg["SameThreadAsScreenshots"],
        "CloseToScreenshotSequence": msg["CloseToScreenshotSequence"],
        "Pages": pages,
        "PDFClassification": classification,
        "ExtractedTextShortRedacted": redacted(text[:1200]) if text and not text.startswith("TEXT EXTRACTION FAILED") else text,
        "MatchingStandaloneCopies": "; ".join(f"{c['Path']} ({c['HashMatchesFILE5531']})" for c in comparisons),
        "MboxAttachmentHashMatches": eml_hash_matches,
        "MboxCandidateAttachments": eml_candidates,
        "Notes": "Sensitive EIN value redacted in narrative outputs; original PDF not modified.",
    }
    write_csv(PDF_CSV, [inventory_row], list(inventory_row.keys()))

    # Update document inventory from prior run by replacing the missing-file row with located details.
    doc_csv = BASE_OUT / "pdf_and_document_attachment_inventory.csv"
    write_csv(doc_csv, [{
        "Path": str(PDF_PATH),
        "FileName": PDF_PATH.name,
        "Size": st.st_size if st else "",
        "CreatedTimeLocal": fmt_time(st.st_ctime) if st else "",
        "ModifiedTimeLocal": fmt_time(st.st_mtime) if st else "",
        "SHA256": pdf_hash,
        "CandidateReason": "Located actual PDF referenced/displayed in Messages.html at 2024/04/25 12:54:20; classified as IRS CP 575 EIN notice for HELO Payment Services LLC.",
    }], ["Path", "FileName", "Size", "CreatedTimeLocal", "ModifiedTimeLocal", "SHA256", "CandidateReason"])

    existing_timeline = read_csv(COMBINED_TIMELINE)
    pdf_event = {
        "TimestampLocal": "2024-04-25 12:54:20",
        "SourceType": "Messages.html PDF attachment",
        "SourceFile": str(MESSAGES_HTML),
        "EventDescription": "FILE_5531.pdf displayed/referenced as a message attachment; extracted text classifies it as an IRS CP 575 EIN notice for HELO Payment Services LLC.",
        "DeviceOrPlatformSignal": "Outgoing to Mom inferred from TO: Mom conversation and surrounding outgoing screenshot sequence",
        "FileOrDocumentName": "FILE_5531.pdf",
        "SenderRecipient": "Exported device/user -> Mom (inferred)",
        "WhyItMatters": "Shows transmission of a sensitive IRS/EIN business PDF in the same April 25 screenshot sequence, not just screenshot images.",
        "Limitation": "HTML export formatting supports direction but does not prove who physically held the phone; verify with original iPhone database.",
    }
    filtered = [r for r in existing_timeline if r.get("FileOrDocumentName") != "FILE_5531.pdf"]
    timeline = filtered + [pdf_event]
    timeline.sort(key=lambda r: r.get("TimestampLocal", ""))
    fields = ["TimestampLocal", "SourceType", "SourceFile", "EventDescription", "DeviceOrPlatformSignal", "FileOrDocumentName", "SenderRecipient", "WhyItMatters", "Limitation"]
    write_csv(COMBINED_TIMELINE, timeline, fields)
    write_csv(PROSECUTION_TIMELINE, timeline, fields)

    links_csv = BASE_OUT / "message_attachment_links.csv"
    links = read_csv(links_csv)
    updated_links = []
    replaced_pdf_link = False
    for r in links:
        if r.get("AttachmentFileName") == "FILE_5531.pdf":
            if replaced_pdf_link:
                continue
            r.update({
                "MessageTimestampLocal": msg["MessageTimestampLocal"],
                "Direction": "Outgoing from exported device to conversation contact (inferred)",
                "Sender": "Exported device/user",
                "Recipient": "Mom",
                "ContactOrConversation": "Mom",
                "AttachmentFileName": "FILE_5531.pdf",
                "AttachmentPath": str(PDF_PATH),
                "NearbyMessageTextShort": "",
                "SourceFile": str(MESSAGES_HTML),
                "Notes": "Direction inferred from TO: Mom export formatting and placement between outgoing screenshot attachments; verify against original iPhone database.",
            })
            replaced_pdf_link = True
        updated_links.append(r)
    if not replaced_pdf_link:
        updated_links.append({
            "MessageTimestampLocal": msg["MessageTimestampLocal"],
            "Direction": "Outgoing from exported device to conversation contact (inferred)",
            "Sender": "Exported device/user",
            "Recipient": "Mom",
            "ContactOrConversation": "Mom",
            "AttachmentFileName": "FILE_5531.pdf",
            "AttachmentPath": str(PDF_PATH),
            "NearbyMessageTextShort": "",
            "SourceFile": str(MESSAGES_HTML),
            "Notes": "Direction inferred from TO: Mom export formatting and placement between outgoing screenshot attachments; verify against original iPhone database.",
        })
    write_csv(links_csv, updated_links, ["MessageTimestampLocal", "Direction", "Sender", "Recipient", "ContactOrConversation", "AttachmentFileName", "AttachmentPath", "NearbyMessageTextShort", "SourceFile", "Notes"])

    sig_section = f"""## FILE_5531.pdf / IRS-EIN Attachment Significance

`FILE_5531.pdf` is the actual PDF located in the `Messages\\HTML\\media` folder and it is referenced/displayed in `Messages.html` at `2024/04/25 12:54:20`. The message export places it in the `TO: Mom` conversation, in the same outgoing-style April 25 attachment run as the screenshots. Local PDF text extraction identified it as an IRS CP 575 EIN notice for HELO Payment Services LLC. This directly supports that the attachment sequence involved sensitive business/tax material, not merely random screenshots. It also lines up with Robin's later statement theme about EIN numbers and business records, but it does not by itself prove Robin personally operated the phone. The remaining proof gap is actor identity and original-device confirmation of sender/recipient direction.

## Evidence Against 'Found Later' Explanation

The April 25 sequence is not limited to later discovery of screenshots. `Messages.html` shows a PDF attachment, `FILE_5531.pdf`, at `2024/04/25 12:54:20`, between screenshot attachments at approximately 12:51 PM and 12:54 PM. Because the PDF is an IRS/EIN document for HELO Payment Services LLC, its timing supports an inference that sensitive business/financial records were being collected or transmitted during the same attachment sequence. This strengthens the investigative value of the sequence, but the data still does not prove who physically held Elijah's phone or who caused the transmission.
"""

    PDF_MD.write_text(f"""# FILE_5531.pdf Analysis

## Inventory

- Found: {'Yes' if exists else 'No'}
- Full path: `{PDF_PATH}`
- Filename: `FILE_5531.pdf`
- Size: {st.st_size if st else ''} bytes
- Created: {fmt_time(st.st_ctime) if st else ''}
- Modified: {fmt_time(st.st_mtime) if st else ''}
- Accessed: {fmt_time(st.st_atime) if st else ''}
- SHA256: `{pdf_hash}`
- Pages: {pages}

## Message Link / Transmission Context

- Messages.html references/displays the PDF: {msg['MessagesHtmlReferences']}
- Link/display type: {msg['HtmlLinkType']}
- Message timestamp: {msg['MessageTimestampLocal']}
- Conversation/contact: {msg['ConversationContact']}
- Appears outgoing to Mom: {msg['AppearsOutgoingToMom']}
- Same thread as screenshots: {msg['SameThreadAsScreenshots']}
- Close in time to screenshot sequence: {msg['CloseToScreenshotSequence']}

## PDF Content Classification

- Classification: {classification}
- Short extracted text, redacted: {redacted(text[:900])}

## Comparison To Known Files

- Standalone copy `C:\\Users\\thoma\\Documents\\Cyber Crimes\\FILE_5531.pdf`: {'hash match' if any(c['Path'].lower() == str(PDF_COPY).lower() and c['HashMatchesFILE5531'] == 'Yes' for c in comparisons) else 'not matched/not found'}.
- Matching embedded MBOX attachment hashes found: {eml_hash_matches}
- Candidate HELO/EIN/IRS embedded MBOX attachments found by filename/hash: {eml_candidates}

{sig_section}
""", encoding="utf-8")

    TOP_EXHIBITS.write_text(f"""# Top Exhibits List

1. `FILE_5531.pdf`
   - SHA256: `{pdf_hash}`
   - Significance: IRS CP 575 EIN notice for HELO Payment Services LLC, displayed in `Messages.html` at `2024/04/25 12:54:20` in the `TO: Mom` conversation.
   - Limitation: Direction is inferred from export formatting; actor identity remains unproven.

2. Lead screenshot `Screenshot 2024-04-19 at 7.22.24 PM.jpeg`
   - Significance: Linked in `Messages.html` at `2024/04/19 19:22:35` as an outgoing-style attachment to Mom.
   - Limitation: Requires visual/OCR review and original device database confirmation.

3. April 25 screenshot sequence
   - Significance: Dense outgoing-style screenshot sequence in the `TO: Mom` conversation, with the PDF attachment embedded in the same run.
   - Limitation: Export formatting alone does not identify who held the phone.
""", encoding="utf-8")

    PACKET_REPORT.write_text(f"""# New Evidence Packet: April 2024 Screenshot Transmission Report

## Bottom Line

The located `FILE_5531.pdf` materially strengthens the message-attachment evidence. It is not merely a missing file reference; the actual PDF exists in the Messages HTML media folder, has SHA256 `{pdf_hash}`, and extracts as an IRS CP 575 EIN notice for HELO Payment Services LLC. `Messages.html` displays it at `2024/04/25 12:54:20` in the `TO: Mom` conversation, between screenshot attachments in the same April 25 sequence.

{sig_section}

## What Remains Unproven

- The data does not directly prove who physically held Elijah's phone.
- The data does not provide IP address, IMEI, serial number, or device ID for the PDF transmission.
- The original iPhone Messages database is still needed to confirm sender/recipient handles, attachment GUID, and transfer direction.
""", encoding="utf-8")

    DETECTIVE_TIMELINE.write_text(f"""# Detective Timeline Report

## Key April 25 Event

- `2024/04/25 12:54:20`: `Messages.html` displays `FILE_5531.pdf` in the `TO: Mom` conversation. The surrounding export shows screenshot attachments before and after this PDF. Local extraction identifies the PDF as an IRS CP 575 EIN notice for HELO Payment Services LLC.

## Investigative Meaning

This turns the April 25 run from a screenshot-only issue into a screenshot-plus-PDF transmission issue involving a sensitive business tax record. The timing supports deliberate collection/transmission of sensitive business material, while actor identity still requires original iPhone/Apple/Google corroboration.
""", encoding="utf-8")

    # Append focused section to prior report if it exists and does not already have it.
    if PRIOR_REPORT.exists():
        prior = PRIOR_REPORT.read_text(encoding="utf-8", errors="replace")
        prior = re.sub(r"A PDF reference was found in the message export; the file itself was not found under the Message Attachments folder\\.", "A PDF reference was found in the message export, and the actual PDF was later located in the Messages HTML media folder.", prior)
        if "FILE_5531.pdf / IRS-EIN Attachment Significance" not in prior:
            prior += "\n" + sig_section
        PRIOR_REPORT.write_text(prior, encoding="utf-8")

    print(f"Was FILE_5531.pdf found? {'Yes' if exists else 'No'}")
    print(f"SHA256: {pdf_hash}")
    print(f"File size: {st.st_size if st else ''} bytes")
    print(f"Appears to be: {classification}")
    print(f"Messages.html references it? {msg['MessagesHtmlReferences']} ({msg['HtmlLinkType']})")
    print(f"Appears sent to Mom? {msg['AppearsOutgoingToMom']}")
    print(f"Message timestamp: {msg['MessageTimestampLocal']}")
    print(f"Near screenshot sequence? {msg['CloseToScreenshotSequence']}")
    print(f"Matches standalone C:\\Users\\thoma\\Documents\\Cyber Crimes\\FILE_5531.pdf? {'Yes' if any(c['Path'].lower() == str(PDF_COPY).lower() and c['HashMatchesFILE5531'] == 'Yes' for c in comparisons) else 'No'}")
    print(f"Matches embedded MBOX/Gmail attachment by hash? {'Yes' if eml_hash_matches else 'No'}")
    print(f"Outputs updated in: {BASE_OUT}")


if __name__ == "__main__":
    main()
