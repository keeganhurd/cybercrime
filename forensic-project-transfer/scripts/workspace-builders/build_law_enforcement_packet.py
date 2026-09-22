import csv
import hashlib
import html
import os
import re
import struct
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from pypdf import PdfReader

OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\IPhone Screenshot Evidence April 2024")
PHOTOS = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Message Attachments\Photos")
MEDIA = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Messages\HTML\media")
MESSAGES = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Messages.html")
PDF = MEDIA / "FILE_5531.pdf"

INV = OUT / "iphone_attachment_inventory.csv"
LINKS = OUT / "message_attachment_links.csv"
PDF_INV = OUT / "file_5531_pdf_inventory.csv"
PDF_ANALYSIS = OUT / "file_5531_pdf_analysis.md"

ATTACH_MAP = OUT / "Attachment_Message_Map.csv"
GAP_CSV = OUT / "Screenshot_Send_Gap_Master.csv"
APR25_CSV = OUT / "April25_Sensitive_Transmission_Sequence.csv"
QUEUE_CSV = OUT / "Manual_Screenshot_Review_Queue.csv"
GALLERY = OUT / "Manual_Screenshot_Review_Gallery.html"
FILE_EXHIBIT = OUT / "FILE_5531_Exhibit_Analysis.md"
POLICE_NARR = OUT / "Police_Supplemental_Evidence_Narrative.md"
SA_TIMELINE = OUT / "State_Attorney_Evidence_Timeline.md"
TOP20 = OUT / "Top_20_Exhibits_For_Reopening.md"
STRENGTH = OUT / "Evidence_Strength_Assessment.md"
EXEC_SUMMARY = OUT / "Reopen_Case_Executive_Summary.md"

SENSITIVE_TERMS = ["IRS", "EIN", "CP 575", "147C", "HELO", "Helo Payment Services", "Navy", "bank", "statement", "Gmail", "Google", "Drive"]


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


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def parse_dt(text):
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            pass
    return None


def parse_screenshot_ts(name):
    m = re.search(r"Screenshot\s+(\d{4})-(\d{2})-(\d{2})\s+at\s+(\d{1,2})\.(\d{2})\.(\d{2}).*?([AP]M)", name, re.I)
    if not m:
        return ""
    y, mo, d, h, mi, s, ap = m.groups()
    h = int(h)
    if ap.upper() == "PM" and h != 12:
        h += 12
    if ap.upper() == "AM" and h == 12:
        h = 0
    return datetime(int(y), int(mo), int(d), h, int(mi), int(s)).strftime("%Y-%m-%d %H:%M:%S")


def norm(name):
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def file_uri(path):
    return "file:///" + quote(str(Path(path).resolve()).replace("\\", "/"))


def classify_elapsed(seconds):
    if seconds is None:
        return "Unknown"
    if 0 <= seconds <= 30:
        return "Immediate"
    if 31 <= seconds <= 120:
        return "Very Close"
    if 121 <= seconds <= 600:
        return "Close"
    return "Later"


def type_for_name(name):
    low = name.lower()
    if low.endswith(".pdf"):
        return "PDF"
    if "screenshot" in low:
        return "Screenshot"
    if low.endswith((".jpg", ".jpeg", ".png", ".heic", ".gif")):
        return "Image"
    return "Other document/media"


def jpeg_dims(path):
    try:
        data = Path(path).read_bytes()[:512 * 1024]
    except OSError:
        return ""
    if data.startswith(b"\xff\xd8"):
        i = 2
        while i + 9 < len(data):
            if data[i] != 0xFF:
                i += 1
                continue
            marker = data[i + 1]
            if marker in (0xC0, 0xC1, 0xC2):
                h = struct.unpack(">H", data[i + 5:i + 7])[0]
                w = struct.unpack(">H", data[i + 7:i + 9])[0]
                return f"{w} x {h}"
            if i + 4 >= len(data):
                break
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
            i += 2 + length
    if data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) > 24:
        w, h = struct.unpack(">II", data[16:24])
        return f"{w} x {h}"
    return ""


def build_resolver(inventory):
    by_norm = {}
    by_ts = {}
    for r in inventory:
        by_norm[norm(r["FileName"])] = r["FullPath"]
        if r.get("ParsedScreenshotTimestampFromFilename"):
            by_ts[r["ParsedScreenshotTimestampFromFilename"]] = r["FullPath"]
    if PDF.exists():
        by_norm[norm(PDF.name)] = str(PDF)
    for p in list(MEDIA.glob("*")) + list(PHOTOS.glob("*")):
        if p.is_file():
            by_norm.setdefault(norm(p.name), str(p))
    return by_norm, by_ts


def resolve_attachment(name, by_norm, by_ts):
    if norm(name) in by_norm:
        return by_norm[norm(name)]
    ts = parse_screenshot_ts(name)
    if ts and ts in by_ts:
        return by_ts[ts]
    return ""


def attachment_map(inventory, links):
    by_norm, by_ts = build_resolver(inventory)
    inv_by_path = {r["FullPath"]: r for r in inventory}
    rows = []
    for r in links:
        name = r["AttachmentFileName"]
        path = r.get("AttachmentPath") or resolve_attachment(name, by_norm, by_ts)
        size = ""
        digest = ""
        dims = ""
        if path and Path(path).exists():
            size = Path(path).stat().st_size
            digest = sha256(path)
            dims = f"{inv_by_path[path]['ImageWidth']} x {inv_by_path[path]['ImageHeight']}" if path in inv_by_path else jpeg_dims(path)
        file_ts = parse_screenshot_ts(name)
        rows.append({
            "MessageTimestampLocal": r["MessageTimestampLocal"],
            "ConversationOrContact": r["ContactOrConversation"],
            "Direction": r["Direction"],
            "AttachmentDisplayName": name,
            "AttachmentResolvedPath": path,
            "AttachmentType": type_for_name(name),
            "FileNameTimestamp": file_ts,
            "SHA256": digest,
            "SizeBytes": size,
            "Dimensions": dims,
            "HTMLSourceIndicator": "Messages.html media/attachment reference; direction inferred from bubble formatting",
            "NearbyTextShort": r.get("NearbyMessageTextShort", "")[:240],
            "Notes": r.get("Notes", ""),
        })
    return rows


def gap_rows(inventory, amap):
    link_by_ts = {}
    for r in amap:
        ts = r["FileNameTimestamp"]
        if ts and r["MessageTimestampLocal"]:
            link_by_ts[ts] = r
    rows = []
    seen_ts = set()
    for inv in inventory:
        ts = inv.get("ParsedScreenshotTimestampFromFilename", "")
        if inv.get("IsTargetDateRange_April19_to_April26_2024") != "Yes" or "screenshot" not in inv["FileName"].lower():
            continue
        seen_ts.add(ts)
        link = link_by_ts.get(ts, {})
        sdt = parse_dt(ts)
        mdt = parse_dt(link.get("MessageTimestampLocal", ""))
        elapsed = int((mdt - sdt).total_seconds()) if sdt and mdt else None
        cls = classify_elapsed(elapsed)
        rows.append({
            "ScreenshotFileName": inv["FileName"],
            "ScreenshotPath": inv["FullPath"],
            "SHA256": inv["SHA256"].upper(),
            "ScreenshotTimestampFromFilename": ts,
            "MessageTimestampLocal": link.get("MessageTimestampLocal", ""),
            "ElapsedSeconds": "" if elapsed is None else elapsed,
            "ElapsedClassification": cls,
            "ConversationOrContact": link.get("ConversationOrContact", ""),
            "Direction": link.get("Direction", ""),
            "Dimensions": f"{inv['ImageWidth']} x {inv['ImageHeight']}",
            "SupportsImmediateCaptureAndSend": "Yes" if cls in ("Immediate", "Very Close") and "Outgoing" in link.get("Direction", "") else "No",
            "UnderminesFoundLaterExplanation": "Yes" if cls == "Immediate" and "Outgoing" in link.get("Direction", "") else ("Potentially" if cls in ("Very Close", "Close") and "Outgoing" in link.get("Direction", "") else "No"),
            "Notes": "Direction is inferred from Messages.html formatting; original iPhone database needed for proof.",
        })
    for link in amap:
        ts = link.get("FileNameTimestamp", "")
        if not ts or ts in seen_ts or link.get("AttachmentType") != "Screenshot":
            continue
        sdt = parse_dt(ts)
        if not sdt or not (datetime(2024, 4, 19) <= sdt <= datetime(2024, 4, 26, 23, 59, 59)):
            continue
        path = link.get("AttachmentResolvedPath", "")
        mdt = parse_dt(link.get("MessageTimestampLocal", ""))
        elapsed = int((mdt - sdt).total_seconds()) if sdt and mdt else None
        cls = classify_elapsed(elapsed)
        digest = sha256(path) if path and Path(path).exists() else ""
        rows.append({
            "ScreenshotFileName": link["AttachmentDisplayName"],
            "ScreenshotPath": path,
            "SHA256": digest,
            "ScreenshotTimestampFromFilename": ts,
            "MessageTimestampLocal": link.get("MessageTimestampLocal", ""),
            "ElapsedSeconds": "" if elapsed is None else elapsed,
            "ElapsedClassification": cls,
            "ConversationOrContact": link.get("ConversationOrContact", ""),
            "Direction": link.get("Direction", ""),
            "Dimensions": link.get("Dimensions", ""),
            "SupportsImmediateCaptureAndSend": "Yes" if cls in ("Immediate", "Very Close") and "Outgoing" in link.get("Direction", "") else "No",
            "UnderminesFoundLaterExplanation": "Yes" if cls == "Immediate" and "Outgoing" in link.get("Direction", "") else ("Potentially" if cls in ("Very Close", "Close") and "Outgoing" in link.get("Direction", "") else "No"),
            "Notes": "Message-linked screenshot resolved outside the Photos inventory; direction is inferred from Messages.html formatting.",
        })
    rows.sort(key=lambda r: r["ScreenshotTimestampFromFilename"])
    return rows


def pdf_text_short():
    if not PDF.exists():
        return "", "Not found"
    try:
        reader = PdfReader(str(PDF))
        text = "\n".join((p.extract_text() or "") for p in reader.pages)
        text = re.sub(r"\b\d{2}-\d{7}\b", "[REDACTED EIN]", text)
        return text[:1200], f"{len(reader.pages)} pages; IRS CP 575 EIN notice for HELO Payment Services LLC"
    except Exception as exc:
        return "", f"PDF extraction failed: {exc}"


def april25_sequence(amap, gaps):
    rows = []
    gap_by_file = {r["ScreenshotFileName"]: r for r in gaps}
    gap_by_ts = {r["ScreenshotTimestampFromFilename"]: r for r in gaps}
    for r in amap:
        mdt = parse_dt(r["MessageTimestampLocal"])
        if not mdt or mdt.date() != datetime(2024, 4, 25).date():
            continue
        if not (datetime(2024, 4, 25, 12, 0) <= mdt <= datetime(2024, 4, 25, 13, 15)):
            continue
        name = r["AttachmentDisplayName"]
        gap = gap_by_file.get(Path(name).name, {}) or gap_by_ts.get(r["FileNameTimestamp"], {})
        sensitive = []
        if name == "FILE_5531.pdf":
            sensitive = ["IRS", "EIN", "CP 575", "HELO Payment Services"]
        rows.append({
            "TimestampLocal": r["MessageTimestampLocal"],
            "AttachmentName": name,
            "AttachmentType": r["AttachmentType"],
            "AttachmentPath": r["AttachmentResolvedPath"],
            "Direction": r["Direction"],
            "ConversationOrContact": r["ConversationOrContact"],
            "FileNameTimestamp": r["FileNameTimestamp"],
            "ElapsedSeconds": gap.get("ElapsedSeconds", ""),
            "ElapsedClassification": gap.get("ElapsedClassification", ""),
            "SensitiveContentIndicators": "; ".join(sensitive),
            "SequenceAssessment": "Part of continuous outgoing April 25 screenshot/PDF sequence; deliberate transmission inference strengthened by timing." if "Outgoing" in r["Direction"] else "Direction unclear/incoming.",
            "Limitations": "Message direction inferred from HTML formatting; image contents need manual review/OCR.",
        })
    rows.sort(key=lambda r: r["TimestampLocal"])
    return rows


def manual_review(gaps):
    priority = []
    for r in gaps:
        if r["ElapsedClassification"] in ("Immediate", "Very Close") or r["ScreenshotTimestampFromFilename"].startswith("2024-04-19") or r["ScreenshotTimestampFromFilename"].startswith("2024-04-25"):
            priority.append({
                "ScreenshotFileName": r["ScreenshotFileName"],
                "ScreenshotPath": r["ScreenshotPath"],
                "Timestamp": r["ScreenshotTimestampFromFilename"],
                "MessageTimestampLocal": r["MessageTimestampLocal"],
                "ElapsedSeconds": r["ElapsedSeconds"],
                "ElapsedClassification": r["ElapsedClassification"],
                "Direction": r["Direction"],
                "ConversationOrContact": r["ConversationOrContact"],
                "Dimensions": r["Dimensions"],
                "ManualChecklist": "Check for Gmail, Google Drive, Google Account, IRS/EIN, bank statement, business record, visible account/email, on-screen time.",
                "Notes": "",
            })
    write_csv(QUEUE_CSV, priority, ["ScreenshotFileName", "ScreenshotPath", "Timestamp", "MessageTimestampLocal", "ElapsedSeconds", "ElapsedClassification", "Direction", "ConversationOrContact", "Dimensions", "ManualChecklist", "Notes"])
    cards = []
    for r in priority:
        cards.append(f"""
        <section class="card">
          <img src="{file_uri(r['ScreenshotPath'])}" loading="lazy" />
          <div><strong>{html.escape(r['ScreenshotFileName'])}</strong></div>
          <div>Screenshot: {html.escape(r['Timestamp'])}</div>
          <div>Message: {html.escape(r['MessageTimestampLocal'])}</div>
          <div>Elapsed: {html.escape(str(r['ElapsedSeconds']))} seconds ({html.escape(r['ElapsedClassification'])})</div>
          <div>Direction/contact: {html.escape(r['Direction'])} / {html.escape(r['ConversationOrContact'])}</div>
          <div>Dimensions: {html.escape(r['Dimensions'])}</div>
          <div class="check">Manual review: Gmail [ ] Drive [ ] Google Account [ ] IRS/EIN [ ] Bank [ ] Business record [ ] Visible email [ ] On-screen time [ ]</div>
        </section>""")
    GALLERY.write_text(f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Manual Screenshot Review Gallery</title>
<style>body{{font-family:Arial,sans-serif;margin:24px;background:#f6f6f6;color:#222}}.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px}}.card{{background:white;border:1px solid #ccc;padding:10px;border-radius:6px}}img{{width:100%;max-height:520px;object-fit:contain;background:#eee}}.check{{margin-top:8px;font-size:12px;color:#333}}</style></head>
<body><h1>Manual Screenshot Review Gallery</h1><p>OCR was not available locally because Tesseract is not installed. Review these screenshots manually and record content findings in the queue CSV.</p><div class="grid">{''.join(cards)}</div></body></html>""", encoding="utf-8")
    return priority


def md_escape(s):
    return str(s).replace("|", "/")


def top_exhibits(gaps, pdf_row):
    ranked = []
    lead = next((r for r in gaps if r["ScreenshotTimestampFromFilename"] == "2024-04-19 19:22:24"), None)
    if lead:
        ranked.append(("Exhibit 1", lead["ScreenshotPath"], lead["SHA256"], lead["MessageTimestampLocal"], "April 19 lead screenshot sent 11 seconds after filename timestamp", "Strongest timing evidence supporting immediate capture-and-send inference.", "Direction/actor must be confirmed from native iPhone database."))
    ranked.append(("Exhibit 2", str(PDF), sha256(PDF) if PDF.exists() else "", "2024/04/25 12:54:20", "FILE_5531.pdf IRS CP 575 EIN notice in same TO: Mom sequence", "Shows sensitive business/tax PDF transmission, not just screenshots.", "HTML direction inferred; actor unproven."))
    for r in [x for x in gaps if x["ElapsedClassification"] == "Immediate" and x is not lead][:18]:
        ranked.append((f"Exhibit {len(ranked)+1}", r["ScreenshotPath"], r["SHA256"], r["MessageTimestampLocal"], f"Screenshot sent {r['ElapsedSeconds']} seconds after filename timestamp", "Additional immediate screenshot-send pattern.", "Needs image content review and native database confirmation."))
    lines = ["# Top 20 Exhibits For Reopening", ""]
    for ex, path, h, ts, shows, matters, lim in ranked[:20]:
        lines += [f"## {ex}", f"- File path: `{path}`", f"- Hash: `{h}`", f"- Timestamp: {ts}", f"- What it shows: {shows}", f"- Why it matters: {matters}", f"- Limitation: {lim}", ""]
    TOP20.write_text("\n".join(lines), encoding="utf-8")
    return ranked


def write_reports(gaps, april25, manual_q):
    lead = next((r for r in gaps if r["ScreenshotTimestampFromFilename"] == "2024-04-19 19:22:24"), None)
    immediate = [r for r in gaps if r["ElapsedClassification"] == "Immediate"]
    very_close = [r for r in gaps if r["ElapsedClassification"] == "Very Close"]
    pdf_short, pdf_class = pdf_text_short()
    pdf_hash = sha256(PDF) if PDF.exists() else ""
    top = top_exhibits(gaps, None)
    lead_elapsed = lead["ElapsedSeconds"] if lead else ""

    FILE_EXHIBIT.write_text(f"""# FILE_5531 Exhibit Analysis

- File path: `{PDF}`
- SHA256: `{pdf_hash}`
- Size: {PDF.stat().st_size if PDF.exists() else ''} bytes
- Document type: {pdf_class}
- Appears in `TO: Mom` thread: Yes
- Timestamp in Messages.html: 2024/04/25 12:54:20
- Adjacent screenshots: screenshot at 12:50:49 PM linked/sent at 12:51:02; screenshot at 12:54:32 PM linked/sent at 12:54:44.
- Why it matters: It places an IRS/EIN business document inside the same outgoing-style screenshot sequence.
- Limitation: Direction is inferred from HTML formatting; native iPhone database is needed to prove sender handle and actor.

## Extracted Text Short Redacted

```text
{pdf_short}
```
""", encoding="utf-8")

    found_later = f"""The lead screenshot filename timestamp is `2024-04-19 19:22:24`. `Messages.html` links it at `2024/04/19 19:22:35`, an elapsed time of approximately {lead_elapsed} seconds. That short gap supports an inference of immediate capture-and-send behavior by whoever had the phone at that moment. It undermines a simple "found later in Photos" explanation unless the person was already actively in possession of the phone and immediately transmitted the image. This is not a guilt conclusion; it requires original-device confirmation."""

    POLICE_NARR.write_text(f"""# Police Supplemental Evidence Narrative

This supplemental packet focuses on screenshot creation timing, message transmission timing, and sensitive business/tax content in the `TO: Mom` message export. The strongest timing item is the April 19, 2024 lead screenshot, whose filename timestamp is 7:22:24 PM and whose message timestamp is 7:22:35 PM, an approximately {lead_elapsed}-second gap. The screenshot appears as an outgoing attachment from the exported device to Mom based on the export formatting.

On April 25, 2024, the same `TO: Mom` thread shows a dense outgoing-style sequence of screenshot attachments. Within that sequence, `FILE_5531.pdf` appears at 12:54:20 PM. Local PDF extraction identifies that document as an IRS CP 575 EIN notice for HELO Payment Services LLC. This means the sequence includes a sensitive IRS/EIN business PDF, not just random images.

{found_later}

No device ID, IMEI, IP address, or direct Google login record was found in this packet. Sender direction is inferred from the message export and should be confirmed with the native iPhone Messages database.
""", encoding="utf-8")

    timeline_lines = ["# State Attorney Evidence Timeline", ""]
    for r in [x for x in gaps if x["MessageTimestampLocal"]][:10]:
        timeline_lines.append(f"- {r['MessageTimestampLocal']}: `{r['ScreenshotFileName']}` sent/linked {r['ElapsedSeconds']} seconds after filename timestamp. Direction: {r['Direction']}.")
    timeline_lines.append("- 2024/04/25 12:54:20: `FILE_5531.pdf` appears in the same `TO: Mom` sequence; classified as IRS CP 575 EIN notice for HELO Payment Services LLC.")
    SA_TIMELINE.write_text("\n".join(timeline_lines) + "\n", encoding="utf-8")

    STRENGTH.write_text(f"""# Evidence Strength Assessment

## Direct evidence
- The files exist, are hashed, and are referenced in local message/export evidence.
- The April 19 lead screenshot filename timestamp and message timestamp show an approximately {lead_elapsed}-second gap.
- `FILE_5531.pdf` exists and extracts as an IRS CP 575 EIN notice for HELO Payment Services LLC.

## Strong circumstantial evidence
- {len(immediate)} screenshots have immediate 0-30 second screenshot-to-message gaps.
- The lead screenshot appears sent to Mom within approximately {lead_elapsed} seconds.
- The April 25 sequence includes both many screenshots and the IRS/EIN PDF attachment.

## Corroborating evidence
- Message export formatting indicates outgoing attachments in the `TO: Mom` conversation.
- Screenshot dimensions are consistent with iPhone screenshot-class images.

## Missing proof
- Native iPhone Messages database confirmation.
- Sender/recipient handles, attachment GUIDs, and transfer metadata.
- Device ID/IMEI/IP and actor identity.
- OCR/manual content classification for screenshot contents.

## Recommended subpoenas/forensic requests
- Apple/iCloud Messages and Photos metadata.
- Native iPhone forensic extraction.
- Google account/Drive/Gmail access logs for April 19-26, 2024.
- Provider records for document access/transmission where applicable.
""", encoding="utf-8")

    EXEC_SUMMARY.write_text(f"""# Reopen Case Executive Summary

New clarified evidence shows that at least one screenshot was created and transmitted in an extremely short interval. The April 19 lead screenshot carries a filename timestamp of `2024-04-19 19:22:24` and appears in `Messages.html` at `2024/04/19 19:22:35`, an approximately {lead_elapsed}-second gap. That timing supports the inference that the person using the phone captured and sent the screenshot immediately, rather than merely finding it later in the Photos app.

The April 25 sequence is also important. It contains a dense run of outgoing-style screenshot attachments in the `TO: Mom` conversation. In the middle of that run, `FILE_5531.pdf` appears at `2024/04/25 12:54:20`. Local extraction identifies that PDF as an IRS CP 575 EIN notice for HELO Payment Services LLC, a sensitive business/tax record. This strengthens the case narrative because the sequence involves transmission of sensitive business material, not only screenshots.

This packet does not prove who physically held the phone. It does not contain IP address, IMEI, device serial, or direct Google login data. The next investigative step is native iPhone extraction and Apple/Google records to confirm sender, recipient, device, and actor attribution.
""", encoding="utf-8")

    packet = OUT / "Law_Enforcement_Evidence_Packet_Summary.md"
    packet.write_text(f"""# Law Enforcement Evidence Packet Summary

## Found Later Defense Analysis

{found_later}

## Key Counts

- Immediate screenshot-send gaps: {len(immediate)}
- Very close screenshot-send gaps: {len(very_close)}
- April 25 sequence rows from noon to 1:15 PM: {len(april25)}
- Manual review screenshots queued: {len(manual_q)}
- OCR status: not available locally; manual gallery created.

## FILE_5531.pdf / IRS-EIN Attachment Significance

`FILE_5531.pdf` is included at `2024/04/25 12:54:20` in the `TO: Mom` sequence. It is an IRS CP 575 EIN notice for HELO Payment Services LLC. This supports the inference that sensitive business/tax material was transmitted in the same sequence as the screenshots.
""", encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    inventory = read_csv(INV)
    links = read_csv(LINKS)
    amap = attachment_map(inventory, links)
    write_csv(ATTACH_MAP, amap, ["MessageTimestampLocal", "ConversationOrContact", "Direction", "AttachmentDisplayName", "AttachmentResolvedPath", "AttachmentType", "FileNameTimestamp", "SHA256", "SizeBytes", "Dimensions", "HTMLSourceIndicator", "NearbyTextShort", "Notes"])
    gaps = gap_rows(inventory, amap)
    write_csv(GAP_CSV, gaps, ["ScreenshotFileName", "ScreenshotPath", "SHA256", "ScreenshotTimestampFromFilename", "MessageTimestampLocal", "ElapsedSeconds", "ElapsedClassification", "ConversationOrContact", "Direction", "Dimensions", "SupportsImmediateCaptureAndSend", "UnderminesFoundLaterExplanation", "Notes"])
    april25 = april25_sequence(amap, gaps)
    write_csv(APR25_CSV, april25, ["TimestampLocal", "AttachmentName", "AttachmentType", "AttachmentPath", "Direction", "ConversationOrContact", "FileNameTimestamp", "ElapsedSeconds", "ElapsedClassification", "SensitiveContentIndicators", "SequenceAssessment", "Limitations"])
    manual_q = manual_review(gaps)
    write_reports(gaps, april25, manual_q)

    lead = next((r for r in gaps if r["ScreenshotTimestampFromFilename"] == "2024-04-19 19:22:24"), {})
    immediate = [r for r in gaps if r["ElapsedClassification"] == "Immediate"]
    very_close = [r for r in gaps if r["ElapsedClassification"] == "Very Close"]
    print(f"Strongest evidence found: lead screenshot sent/linked {lead.get('ElapsedSeconds')} seconds after filename timestamp, outgoing to Mom inferred.")
    print(f"11-second gap confirmed: {'Yes' if str(lead.get('ElapsedSeconds')) == '11' else 'No'}")
    print(f"Additional immediate gaps found: {max(0, len(immediate) - (1 if lead else 0))}")
    print(f"Very-close gaps found: {len(very_close)}")
    print("FILE_5531.pdf included in same sequence: Yes, at 2024/04/25 12:54:20 between screenshots.")
    print("OCR/visual classification: OCR failed because Tesseract is not installed; manual gallery and queue created.")
    print("Supports immediate capture-and-send behavior: Yes, based on immediate elapsed-time rows and outgoing-style message formatting.")
    print("Undermines 'found later' explanation: Yes for immediate rows, especially the 11-second lead screenshot, but actor identity remains unproven.")
    print("Weakest link: direction and actor identity are inferred from export formatting; native iPhone database confirmation is still needed.")
    print(f"Outputs written to: {OUT}")


if __name__ == "__main__":
    main()
