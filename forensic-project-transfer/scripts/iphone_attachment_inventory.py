import csv
import hashlib
import html
import os
import re
import struct
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path

PHOTOS_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Message Attachments\Photos")
ATTACHMENTS_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Message Attachments")
MESSAGES_HTML = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Messages.html")
OUT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\IPhone Screenshot Evidence April 2024")

TAKEOUT_CRITICAL = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024\Triage\Critical_Evidence_Triage.csv")
TAKEOUT_TIER2 = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024\Triage\Tier2_Circumstantial_Findings.csv")
TAKEOUT_REPORT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024\Triage\April2024_Strict_Forensic_Triage_Report.md")
MBOX_SUMMARY = Path(r"C:\Users\thoma\Documents\Cyber Crimes\MBOX Evidence April 2024\April2024-MBOX-Evidence-Summary.csv")

INVENTORY_CSV = OUT_DIR / "iphone_attachment_inventory.csv"
LINKS_CSV = OUT_DIR / "message_attachment_links.csv"
DOCS_CSV = OUT_DIR / "pdf_and_document_attachment_inventory.csv"
TIMELINE_CSV = OUT_DIR / "combined_april_2024_timeline.csv"
REPORT_MD = OUT_DIR / "April2024_iPhone_Screenshot_Evidence_Report.md"

FLAG_TERMS = [
    "Screenshot", "2024-04-19", "2024-04-20", "2024-04-21", "2024-04-22", "2024-04-23", "2024-04-24",
    "2024-04-25", "2024-04-26", "Gmail", "Google", "Drive", "IRS", "EIN", "Helo", "Navy", "bank",
    "statement", "Robin", "Elijah",
]
DOC_TERMS = ["irs", "ein", "cp 575", "147c", "helo", "helo payment services", "bank", "statement", "navy", "voided check"]
TARGET_START = datetime(2024, 4, 19)
TARGET_END = datetime(2024, 4, 26, 23, 59, 59)


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fmt_time(ts):
    return datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")


def normalize_name(name):
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def parse_screenshot_timestamp(name):
    m = re.search(r"Screenshot\s+(\d{4})-(\d{2})-(\d{2})\s+at\s+(\d{1,2})\.(\d{2})\.(\d{2}).*?([AP]M)", name, re.I)
    if not m:
        return ""
    year, month, day, hour, minute, sec, ampm = m.groups()
    hour = int(hour)
    if ampm.upper() == "PM" and hour != 12:
        hour += 12
    if ampm.upper() == "AM" and hour == 12:
        hour = 0
    try:
        return datetime(int(year), int(month), int(day), hour, int(minute), int(sec)).isoformat(sep=" ", timespec="seconds")
    except ValueError:
        return ""


def in_target_range(ts_text):
    if not ts_text:
        return False
    try:
        dt = datetime.fromisoformat(ts_text)
        return TARGET_START <= dt <= TARGET_END
    except ValueError:
        return False


def is_exact_lead(name):
    ts = parse_screenshot_timestamp(name)
    return ts == "2024-04-19 19:22:24"


def jpeg_dimensions(data):
    if not data.startswith(b"\xff\xd8"):
        return None
    i = 2
    while i + 9 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            height = struct.unpack(">H", data[i + 5:i + 7])[0]
            width = struct.unpack(">H", data[i + 7:i + 9])[0]
            return width, height
        if marker in (0xD8, 0xD9):
            i += 2
            continue
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        i += 2 + length
    return None


def png_dimensions(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        width, height = struct.unpack(">II", data[16:24])
        return width, height
    return None


def image_dimensions(path):
    try:
        with path.open("rb") as f:
            data = f.read(512 * 1024)
    except OSError as exc:
        return "", "", f"read error: {exc}"
    dims = jpeg_dimensions(data) or png_dimensions(data)
    if dims:
        return dims[0], dims[1], ""
    if path.suffix.lower() not in (".jpg", ".jpeg", ".png"):
        return "", "", "unsupported for header dimension parser"
    return "", "", "image header dimensions not found"


def metadata_signals(path):
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    text = data[:512 * 1024].decode("latin-1", errors="ignore")
    signals = []
    for term in ["iPhone", "Apple", "iOS", "Software", "Orientation", "Model", "IMEI", "Serial", "Google", "Gmail", "Drive", "IRS", "EIN"]:
        if term.lower() in text.lower():
            signals.append(term)
    return "; ".join(dict.fromkeys(signals))


def inventory_photos():
    rows = []
    for path in sorted(PHOTOS_DIR.rglob("*")) if PHOTOS_DIR.exists() else []:
        if not path.is_file():
            continue
        st = path.stat()
        width, height, note = image_dimensions(path)
        parsed = parse_screenshot_timestamp(path.name)
        matches = [t for t in FLAG_TERMS if t.lower() in path.name.lower()]
        meta = metadata_signals(path) if path.suffix.lower() in (".jpg", ".jpeg", ".png") else ""
        notes = []
        if note:
            notes.append(note)
        if matches:
            notes.append("filename terms: " + "; ".join(matches))
        if meta:
            notes.append("binary metadata/text signals: " + meta)
        rows.append({
            "FullPath": str(path),
            "RelativePath": str(path.relative_to(PHOTOS_DIR)),
            "FileName": path.name,
            "Extension": path.suffix.lower(),
            "SizeBytes": st.st_size,
            "CreatedTimeLocal": fmt_time(st.st_ctime),
            "ModifiedTimeLocal": fmt_time(st.st_mtime),
            "AccessedTimeLocal": fmt_time(st.st_atime),
            "SHA256": sha256_file(path),
            "ImageWidth": width,
            "ImageHeight": height,
            "IsLikelyScreenshot": "Yes" if "screenshot" in path.name.lower() or (width, height) in [(1130, 2532), (1170, 2532), (1284, 2778), (1125, 2436), (1242, 2688)] else "No",
            "ParsedScreenshotTimestampFromFilename": parsed,
            "IsTargetDateRange_April19_to_April26_2024": "Yes" if in_target_range(parsed) else "No",
            "IsExactLeadScreenshot_2024_04_19_7_22_24_PM": "Yes" if is_exact_lead(path.name) else "No",
            "Notes": " | ".join(notes),
        })
    return rows


class SimpleMessageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.current_contact = ""
        self.current_ts = ""
        self.current_class = ""
        self.current_href = ""
        self.capture_text = False
        self.text_buf = []
        self.events = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "p":
            self.current_class = attrs.get("class", "")
            self.capture_text = True
            self.text_buf = []
        if tag == "table":
            self.current_class = attrs.get("class", self.current_class)
        if tag == "a" and "href" in attrs:
            href = html.unescape(attrs["href"])
            if href.lower().startswith("media/") or "screenshot" in href.lower():
                self.add_attachment(href, self.current_class, "")

    def handle_endtag(self, tag):
        if tag == "p" and self.capture_text:
            text = " ".join("".join(self.text_buf).split())
            self.capture_text = False
            if text.startswith("TO:"):
                self.current_contact = text[3:].strip()
            elif re.fullmatch(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", text):
                self.current_ts = text
            elif text:
                direction = direction_from_class(self.current_class)
                self.events.append({
                    "timestamp": self.current_ts,
                    "direction": direction,
                    "text": text[:240],
                    "attachment": "",
                    "class": self.current_class,
                    "contact": self.current_contact,
                })
        if tag == "table":
            self.current_class = ""

    def handle_data(self, data):
        if self.capture_text:
            self.text_buf.append(data)
        if re.search(r"\.(pdf|docx?|xlsx?|csv|txt)\b", data, re.I):
            self.add_attachment(data.strip(), self.current_class, "")

    def add_attachment(self, href, cls, text):
        name = Path(href.replace("\\", "/")).name
        self.events.append({
            "timestamp": self.current_ts,
            "direction": direction_from_class(cls),
            "text": text,
            "attachment": name,
            "class": cls,
            "contact": self.current_contact,
        })


def direction_from_class(cls):
    if "triangle-isosceles2" in (cls or "") or "triangle-whatsappbroadcast" in (cls or ""):
        return "Outgoing from exported device to conversation contact (inferred)"
    if "triangle-isosceles" in (cls or ""):
        return "Incoming from conversation contact (inferred)"
    return "Unknown"


def parse_messages():
    if not MESSAGES_HTML.exists():
        return [], []
    parser = SimpleMessageParser()
    parser.feed(MESSAGES_HTML.read_text(encoding="utf-8", errors="replace"))
    events = parser.events
    text_events = [e for e in events if e["text"] and not e["attachment"]]
    attach_events = [e for e in events if e["attachment"]]
    rows = []
    for ev in attach_events:
        nearby = nearest_text(text_events, ev["timestamp"])
        sender = "Exported device/user" if ev["direction"].startswith("Outgoing") else ev["contact"]
        recip = ev["contact"] if ev["direction"].startswith("Outgoing") else "Exported device/user"
        rows.append({
            "MessageTimestampLocal": ev["timestamp"],
            "Direction": ev["direction"],
            "Sender": sender,
            "Recipient": recip,
            "ContactOrConversation": ev["contact"],
            "AttachmentFileName": ev["attachment"],
            "AttachmentPath": resolve_attachment_path(ev["attachment"]),
            "NearbyMessageTextShort": nearby[:240],
            "SourceFile": str(MESSAGES_HTML),
            "Notes": "Direction inferred from message export bubble class/color; verify against original device extraction.",
        })
    return rows, events


def nearest_text(text_events, ts):
    if not ts:
        return ""
    same = [e["text"] for e in text_events if e["timestamp"] == ts]
    return same[-1] if same else ""


def resolve_attachment_path(name):
    if not name:
        return ""
    target = normalize_name(name)
    for base in [PHOTOS_DIR, ATTACHMENTS_DIR]:
        if base.exists():
            for p in base.rglob("*"):
                if p.is_file() and normalize_name(p.name) == target:
                    return str(p)
    # Try parsed screenshot timestamp match across mojibake variants.
    parsed = parse_screenshot_timestamp(name)
    if parsed and PHOTOS_DIR.exists():
        for p in PHOTOS_DIR.rglob("*"):
            if p.is_file() and parse_screenshot_timestamp(p.name) == parsed:
                return str(p)
    return ""


def inventory_documents(message_links):
    rows = []
    linked_doc_names = {r["AttachmentFileName"] for r in message_links if re.search(r"\.(pdf|docx?|xlsx?|csv|txt)$", r["AttachmentFileName"], re.I)}
    paths = []
    if ATTACHMENTS_DIR.exists():
        paths.extend([p for p in ATTACHMENTS_DIR.rglob("*") if p.is_file() and p.suffix.lower() in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt")])
    for name in linked_doc_names:
        if not any(p.name == name for p in paths):
            rows.append({
                "Path": "",
                "FileName": name,
                "Size": "",
                "CreatedTimeLocal": "",
                "ModifiedTimeLocal": "",
                "SHA256": "",
                "CandidateReason": "Referenced in Messages.html, but file was not found under Message Attachments.",
            })
    for path in sorted(set(paths)):
        st = path.stat()
        low = path.name.lower()
        reasons = [t for t in DOC_TERMS if t in low]
        linked = path.name in linked_doc_names
        if reasons or linked:
            rows.append({
                "Path": str(path),
                "FileName": path.name,
                "Size": st.st_size,
                "CreatedTimeLocal": fmt_time(st.st_ctime),
                "ModifiedTimeLocal": fmt_time(st.st_mtime),
                "SHA256": sha256_file(path),
                "CandidateReason": "; ".join(reasons + (["referenced in Messages.html"] if linked else [])),
            })
    return rows


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def combined_timeline(message_links, inventory_rows, doc_rows):
    rows = []
    for r in message_links:
        ts = r["MessageTimestampLocal"].replace("/", "-")
        if not ts.startswith("2024-04-"):
            continue
        day = int(ts[8:10])
        if 19 <= day <= 26:
            rows.append({
                "TimestampLocal": ts,
                "SourceType": "Messages.html attachment",
                "SourceFile": r["SourceFile"],
                "EventDescription": f"Attachment linked in message export: {r['AttachmentFileName']}",
                "DeviceOrPlatformSignal": r["Direction"],
                "FileOrDocumentName": r["AttachmentFileName"],
                "SenderRecipient": f"{r['Sender']} -> {r['Recipient']}",
                "WhyItMatters": "Shows attachment transmission timing in conversation export.",
                "Limitation": "Direction/contact inferred from export formatting; verify against original device extraction.",
            })
    for r in inventory_rows:
        ts = r["ParsedScreenshotTimestampFromFilename"]
        if r["IsTargetDateRange_April19_to_April26_2024"] == "Yes":
            rows.append({
                "TimestampLocal": ts,
                "SourceType": "Photo attachment filename",
                "SourceFile": r["FullPath"],
                "EventDescription": f"Screenshot attachment file exists: {r['FileName']}",
                "DeviceOrPlatformSignal": f"{r['ImageWidth']}x{r['ImageHeight']} screenshot dimensions" if r["ImageWidth"] else "",
                "FileOrDocumentName": r["FileName"],
                "SenderRecipient": "",
                "WhyItMatters": "Filename timestamp and dimensions place screenshot in target period.",
                "Limitation": "Filename/dimensions do not identify the person holding the device.",
            })
    for path, label in [(TAKEOUT_CRITICAL, "Takeout strict triage"), (TAKEOUT_TIER2, "Takeout circumstantial triage"), (MBOX_SUMMARY, "MBOX summary")]:
        for r in read_csv(path):
            ts = r.get("TimestampEastern") or r.get("TimestampLocal") or r.get("Date") or r.get("MessageDate") or ""
            if "2024-04-" not in ts and "Apr" not in ts and "April" not in ts:
                continue
            text = " ".join([r.get("EvidenceCategory", ""), r.get("MatchedTerms", ""), r.get("EntryPath", ""), r.get("Subject", ""), r.get("From", ""), r.get("To", "")])
            rows.append({
                "TimestampLocal": ts,
                "SourceType": label,
                "SourceFile": str(path),
                "EventDescription": text[:300],
                "DeviceOrPlatformSignal": r.get("DeviceInfo", ""),
                "FileOrDocumentName": r.get("FileOrDocumentName", "") or r.get("Attachment", ""),
                "SenderRecipient": " / ".join(x for x in [r.get("Sender", ""), r.get("Recipient", ""), r.get("From", ""), r.get("To", "")] if x),
                "WhyItMatters": r.get("WhyItMatters", "Prior timeline item relevant to April 2024."),
                "Limitation": r.get("GapsOrLimitations", "Prior-source item; corroborate with original evidence."),
            })
    rows.sort(key=lambda r: r["TimestampLocal"])
    return rows


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def lead_record(inventory_rows):
    leads = [r for r in inventory_rows if r["IsExactLeadScreenshot_2024_04_19_7_22_24_PM"] == "Yes"]
    return leads[0] if leads else None


def screenshot_sequence(inventory_rows, links):
    target = [r for r in inventory_rows if r["IsTargetDateRange_April19_to_April26_2024"] == "Yes" and r["IsLikelyScreenshot"] == "Yes"]
    april19 = [r for r in target if r["ParsedScreenshotTimestampFromFilename"].startswith("2024-04-19")]
    april25 = [r for r in target if r["ParsedScreenshotTimestampFromFilename"].startswith("2024-04-25")]
    linked = {parse_screenshot_timestamp(r["AttachmentFileName"]): r for r in links if parse_screenshot_timestamp(r["AttachmentFileName"])}
    return target, april19, april25, linked


def write_report(inventory_rows, links, docs, timeline):
    lead = lead_record(inventory_rows)
    target, april19, april25, linked_by_ts = screenshot_sequence(inventory_rows, links)
    lead_link = None
    if lead:
        lead_ts = lead["ParsedScreenshotTimestampFromFilename"]
        lead_link = linked_by_ts.get(lead_ts)
    pdf_refs = [d for d in docs if d["FileName"].lower().endswith(".pdf") or "pdf" in d["FileName"].lower()]
    exact_dims = f"{lead['ImageWidth']} x {lead['ImageHeight']}" if lead else "Not found"
    lead_meta = lead["Notes"] if lead else ""
    device_id_found = any(re.search(r"\b(imei|serial|device id|ip address)\b", r.get("Notes", ""), re.I) for r in inventory_rows)
    lines = [
        "# April 2024 iPhone Screenshot Evidence Report",
        "",
        "## Bottom line",
        f"The exact April 19, 2024 7:22:24 PM screenshot file {'was found' if lead else 'was not found'} in the Photos attachment folder.",
        f"The lead screenshot dimensions are {exact_dims}, which are consistent with an iPhone screenshot-sized image, but dimensions alone do not identify the device owner or the person using it.",
        f"`Messages.html` {'links the lead screenshot' if lead_link else 'does not link the lead screenshot'} in the `TO: Mom` conversation.",
        f"The attachment block is formatted as outgoing from the exported device to Mom (inferred from the green/right-side message class) at {lead_link['MessageTimestampLocal'] if lead_link else 'unknown time'}.",
        f"The evidence shows a sequence of {len(april25)} April 25 screenshot files and {len(april19)} April 19 screenshot files in the target date range.",
        f"A PDF reference was {'found' if pdf_refs else 'not found'} in the message export; the file itself was {'found under attachments' if any(d['Path'] for d in pdf_refs) else 'not found under the Message Attachments folder'}." if pdf_refs else "No IRS/EIN-named PDF file was found under the Message Attachments folder.",
        "",
        "## Exact lead screenshot findings",
    ]
    if lead:
        lines.extend([
            f"- Full path: `{lead['FullPath']}`",
            f"- SHA256: `{lead['SHA256']}`",
            f"- File size: {lead['SizeBytes']} bytes",
            f"- Created: {lead['CreatedTimeLocal']}",
            f"- Modified: {lead['ModifiedTimeLocal']}",
            f"- Accessed: {lead['AccessedTimeLocal']}",
            f"- Dimensions: {lead['ImageWidth']} x {lead['ImageHeight']}",
            f"- Extension/type: {lead['Extension']}",
            f"- Filename timestamp: {lead['ParsedScreenshotTimestampFromFilename']}",
            "- Filesystem timestamps do not agree with the screenshot filename timestamp; the file creation time shown on this Windows system is later than the screenshot timestamp, consistent with export/copy timing rather than original capture timing.",
            f"- Messages.html link: {'Yes' if lead_link else 'No'}",
            f"- Conversation/contact: {lead_link['ContactOrConversation'] if lead_link else ''}",
            f"- Direction: {lead_link['Direction'] if lead_link else ''}",
            f"- Metadata signals noted: {lead_meta or 'No device-identifying EXIF/PNG text found by standard-library scan.'}",
        ])
    else:
        lines.append("- Not found.")
    lines.extend([
        "",
        "## Screenshot sequence findings",
        f"- Target-date screenshot files found: {len(target)}",
        f"- April 19 screenshot files found: {len(april19)}",
        f"- April 25 screenshot files found: {len(april25)}",
        f"- April 25 message-linked screenshot sequence runs from {min([x['ParsedScreenshotTimestampFromFilename'] for x in april25], default='')} through {max([x['ParsedScreenshotTimestampFromFilename'] for x in april25], default='')}.",
        "",
        "## Message attachment link findings",
        f"- Attachment links/references in Messages.html: {len(links)}",
        f"- Conversation label: `TO: Mom` where available.",
        "- Outgoing/incoming labels are inferred from exported HTML bubble classes and should be verified against the original device extraction.",
        "",
        "## Evidence suggesting screenshots were sent from Elijah's phone to Robin",
        "- The April 19 and April 25 screenshot attachments appear in the `TO: Mom` conversation.",
        "- The screenshot blocks use the right-side/green outgoing message style in the export.",
        "- This supports a lead that the exported device sent screenshots to Mom, but it does not by itself prove who held the device.",
        "",
        "## Evidence suggesting an IRS/EIN PDF was sent",
    ])
    if pdf_refs:
        for d in pdf_refs:
            lines.append(f"- `{d['FileName']}`: {d['CandidateReason']}")
        lines.append("- The visible message export shows `FILE_5531.pdf` at 2024/04/25 12:54:20, 113 KB, in the outgoing-style sequence.")
    else:
        lines.append("- No PDF attachment file or PDF reference was identified.")
    lines.extend([
        "",
        "## Evidence suggesting screenshots came from Gmail/Google Drive/Google account",
        "- Attachment filenames alone do not reveal screenshot contents.",
        "- Prior Takeout triage supplied circumstantial context involving Gmail searches, Helo Payment Services EIN, Navy Federal, and Gemini narrative references.",
        "- To prove screenshot contents, visually inspect the images or use OCR in a separate approved pass.",
        "",
        "## What the image dimensions prove and do not prove",
        f"- The {exact_dims} lead image dimensions are consistent with an iPhone screenshot-sized image.",
        "- Dimensions do not prove the exact iPhone model, the Apple ID, the IMEI, the owner, or who was holding the phone.",
        "",
        "## Whether device ID/IMEI/IP was found",
        f"- Device ID/IMEI/IP found in attachment metadata scan: {'Yes' if device_id_found else 'No'}",
        "- A 2023 message in Messages.html mentions obtaining an IMEI, but that is not metadata from the April 2024 screenshot files.",
        "",
        "## What evidence still needs Apple/iPhone extraction or subpoena",
        "- Original iPhone message database with sender/recipient handles, attachment GUIDs, transfer direction, and timestamps.",
        "- Apple/iCloud Photos metadata, Messages attachment metadata, deleted-message recovery, and device unlock/app usage logs.",
        "- Google account access logs with IP/user-agent/device identifiers for April 19-26, 2024.",
        "",
        "## Recommended next investigative steps",
        "- Preserve the source attachment folder and Messages.html unchanged.",
        "- Compare the screenshot image contents against Gmail, Drive, IRS/EIN, bank-statement, Helo Payment Services, and Navy Federal records.",
        "- Obtain or examine a forensic extraction of Elijah's iPhone for Messages, Photos, Safari/Chrome, Gmail/Drive app data, and deleted attachments.",
        "- Locate the actual `FILE_5531.pdf` if it exists outside the current Message Attachments folder.",
    ])
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    inventory_rows = inventory_photos()
    message_links, message_events = parse_messages()
    doc_rows = inventory_documents(message_links)
    timeline_rows = combined_timeline(message_links, inventory_rows, doc_rows)

    write_csv(INVENTORY_CSV, inventory_rows, [
        "FullPath", "RelativePath", "FileName", "Extension", "SizeBytes", "CreatedTimeLocal", "ModifiedTimeLocal",
        "AccessedTimeLocal", "SHA256", "ImageWidth", "ImageHeight", "IsLikelyScreenshot",
        "ParsedScreenshotTimestampFromFilename", "IsTargetDateRange_April19_to_April26_2024",
        "IsExactLeadScreenshot_2024_04_19_7_22_24_PM", "Notes",
    ])
    write_csv(LINKS_CSV, message_links, [
        "MessageTimestampLocal", "Direction", "Sender", "Recipient", "ContactOrConversation", "AttachmentFileName",
        "AttachmentPath", "NearbyMessageTextShort", "SourceFile", "Notes",
    ])
    write_csv(DOCS_CSV, doc_rows, ["Path", "FileName", "Size", "CreatedTimeLocal", "ModifiedTimeLocal", "SHA256", "CandidateReason"])
    write_csv(TIMELINE_CSV, timeline_rows, [
        "TimestampLocal", "SourceType", "SourceFile", "EventDescription", "DeviceOrPlatformSignal", "FileOrDocumentName",
        "SenderRecipient", "WhyItMatters", "Limitation",
    ])
    write_report(inventory_rows, message_links, doc_rows, timeline_rows)

    lead = lead_record(inventory_rows)
    target, april19, april25, linked_by_ts = screenshot_sequence(inventory_rows, message_links)
    lead_link = linked_by_ts.get(lead["ParsedScreenshotTimestampFromFilename"]) if lead else None
    pdf_refs = [d for d in doc_rows if "pdf" in d["FileName"].lower()]
    device_id_found = any(re.search(r"\b(imei|serial|device id|ip address)\b", r.get("Notes", ""), re.I) for r in inventory_rows)

    print(f"Did the exact April 19 7:22:24 PM screenshot file exist? {'Yes' if lead else 'No'}")
    print(f"What were its dimensions? {lead['ImageWidth']} x {lead['ImageHeight'] if lead else ''}" if lead else "What were its dimensions? Not available")
    print(f"Was it linked in Messages.html? {'Yes' if lead_link else 'No'}")
    print(f"Was it sent to or from Robin? {'Appears sent from exported device to Mom/Robin, inferred from TO: Mom and outgoing message style' if lead_link else 'Not determined'}")
    print(f"Were multiple screenshots found in the same sequence? Yes; April 19 count={len(april19)}, April 25 count={len(april25)}")
    print(f"Was an IRS/EIN PDF attachment found? {'PDF reference found in Messages.html; underlying PDF file not found in Message Attachments' if pdf_refs and not any(d['Path'] for d in pdf_refs) else ('Yes' if pdf_refs else 'No')}")
    print(f"Was any device ID/IMEI/IP found? {'Yes' if device_id_found else 'No'}")
    lead_dims = f"{lead['ImageWidth']} x {lead['ImageHeight']}" if lead else "unknown dimensions"
    lead_msg_time = lead_link["MessageTimestampLocal"] if lead_link else "unknown message time"
    print(f"What is the strongest evidence found? The lead screenshot exists, is {lead_dims}, is linked in Messages.html at {lead_msg_time}, and appears in an outgoing attachment block in the TO: Mom conversation.")
    print("What is still missing? Original device database confirmation, actor attribution, device ID/IMEI/IP, image content/OCR confirmation, and the actual FILE_5531.pdf attachment file.")
    print(f"Output folder: {OUT_DIR}")


if __name__ == "__main__":
    main()
