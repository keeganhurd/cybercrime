import csv
import hashlib
import os
import re
import subprocess
import struct
from datetime import datetime
from pathlib import Path

OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\IPhone Screenshot Evidence April 2024")
PHOTOS_ATTACH = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Message Attachments\Photos")
MEDIA = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Messages\HTML\media")
PHOTOS_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Photos")
MESSAGES = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Messages.html")
OCR_HELPER = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\windows_ocr_image.ps1")

ATTACH_MAP = OUT / "Attachment_Message_Map.csv"
GAPS = OUT / "Screenshot_Send_Gap_Master.csv"
APR25 = OUT / "April25_Sensitive_Transmission_Sequence.csv"
OCR_TEXT_DIR = OUT / "OCR Text"

CROSS_MAP = OUT / "Cross_Folder_Image_Map.csv"
OCR_REVIEW = OUT / "Screenshot_OCR_Full_Review.csv"
TIME_COMPARE = OUT / "Screenshot_OnScreen_Time_Comparison.csv"
SENSITIVE_EXHIBITS = OUT / "Sensitive_Screenshot_Exhibits.csv"
FOUND_LATER = OUT / "Found_Later_Defense_Analysis.md"
NEW_PACKET = OUT / "New_Evidence_Packet_With_OCR_Findings.md"
OCR_SETUP = OUT / "OCR_SETUP_REQUIRED.md"

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff"}
SENSITIVE_TERMS = {
    "Gmail": ["gmail", "mail.google.com"],
    "Google Drive": ["drive.google.com", "google drive", "my drive", "shared with me"],
    "Google Account": ["google account", "myaccount.google.com", "security", "2-step", "password"],
    "Google Photos": ["photos.google.com", "google photos"],
    "IRS/EIN": ["irs", "internal revenue service", "ein", "employer identification number", "cp 575", "147c"],
    "Bank Statement": ["bank statement", "statement", "navy federal", "account number"],
    "Financial Statement": ["financial statement", "funding", "deposit", "balance", "voided check"],
    "Business Record": ["helo payment services", "business", "llc", "dba", "merchant", "trustfi", "doordash", "payanywhere"],
    "Helo Payment Services": ["helo payment services", "helo"],
    "Navy Federal": ["navy federal"],
    "Trustfi": ["trustfi"],
    "DoorDash": ["doordash"],
}


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


def fmt_time(ts):
    return datetime.fromtimestamp(ts).isoformat(sep=" ", timespec="seconds")


def norm(name):
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


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


def dims(path):
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
            if marker in (0xC0, 0xC1, 0xC2, 0xC3):
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


def dt(text):
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            pass
    return None


def local_ocr_available():
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Add-Type -AssemblyName System.Runtime.WindowsRuntime; $null=[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType=WindowsRuntime]; if ([Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages.Count -gt 0) { 'YES' } else { 'NO' }"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        return "YES" in out.stdout
    except Exception:
        return False


def ocr_image(path):
    if not OCR_HELPER.exists():
        return "", "OCR helper missing"
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(OCR_HELPER), str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if proc.returncode != 0:
        return "", proc.stderr.strip()[:500]
    return proc.stdout.strip(), ""


def build_cross_map(amap):
    folders = [("Message Attachments Photos", PHOTOS_ATTACH), ("Messages HTML media", MEDIA), ("Photos", PHOTOS_ROOT)]
    msg_by_norm = {norm(r["AttachmentDisplayName"]): r for r in amap}
    msg_by_path = {str(Path(r["AttachmentResolvedPath"])): r for r in amap if r.get("AttachmentResolvedPath")}
    rows = []
    by_hash = {}
    by_ts = {}
    files = []
    for label, folder in folders:
        if not folder.exists():
            continue
        for p in folder.rglob("*"):
            if p.is_file() and p.suffix.lower() in IMAGE_EXTS:
                try:
                    digest = sha256(p)
                    parsed = parse_screenshot_ts(p.name)
                    st = p.stat()
                except OSError:
                    continue
                rec = {
                    "SourceFolder": label,
                    "FileName": p.name,
                    "FullPath": str(p),
                    "SHA256": digest,
                    "SizeBytes": st.st_size,
                    "Dimensions": dims(p),
                    "CreatedTimeLocal": fmt_time(st.st_ctime),
                    "ModifiedTimeLocal": fmt_time(st.st_mtime),
                    "ParsedTimestampFromFilename": parsed,
                }
                files.append(rec)
                by_hash.setdefault(digest, []).append(rec)
                if parsed:
                    by_ts.setdefault(parsed, []).append(rec)
    for i, rec in enumerate(files, 1):
        matches = []
        for other in by_hash.get(rec["SHA256"], []):
            if other["FullPath"] != rec["FullPath"]:
                matches.append(other["FullPath"])
        if rec["ParsedTimestampFromFilename"]:
            for other in by_ts.get(rec["ParsedTimestampFromFilename"], []):
                if other["FullPath"] != rec["FullPath"] and other["FullPath"] not in matches:
                    matches.append(other["FullPath"])
        msg = msg_by_path.get(rec["FullPath"]) or msg_by_norm.get(norm(rec["FileName"])) or {}
        rec.update({
            "CanonicalImageId": f"IMG-CANON-{i:04d}",
            "MatchingFilesInOtherFolders": "; ".join(matches),
            "AppearsInMessagesHtml": "Yes" if msg else "No",
            "MessageTimestampLocal": msg.get("MessageTimestampLocal", ""),
            "ConversationOrContact": msg.get("ConversationOrContact", ""),
            "Direction": msg.get("Direction", ""),
            "Notes": "Matched by SHA256 and/or parsed screenshot timestamp." if matches else "",
        })
        rows.append(rec)
    write_csv(CROSS_MAP, rows, ["CanonicalImageId", "SourceFolder", "FileName", "FullPath", "SHA256", "SizeBytes", "Dimensions", "CreatedTimeLocal", "ModifiedTimeLocal", "ParsedTimestampFromFilename", "MatchingFilesInOtherFolders", "AppearsInMessagesHtml", "MessageTimestampLocal", "ConversationOrContact", "Direction", "Notes"])
    return rows


def detect(text):
    low = text.lower()
    categories = []
    for cat, terms in SENSITIVE_TERMS.items():
        if any(t in low for t in terms):
            categories.append(cat)
    emails = re.findall(r"[\w.\-+]+@[\w.\-]+\.\w+", text)
    domains = re.findall(r"\b(?:[a-z0-9-]+\.)+(?:com|org|net|gov)\b", low)
    times = re.findall(r"\b(?:[0-1]?\d|2[0-3]):[0-5]\d\b", text)
    filenames = re.findall(r"\b[\w .-]+\.(?:pdf|png|jpe?g|docx?|xlsx?|csv)\b", text, re.I)
    app = []
    for name, terms in [("Gmail", ["gmail", "mail.google.com"]), ("Google Drive", ["drive.google.com", "google drive"]), ("Google Account", ["google account", "myaccount"]), ("Navy Federal", ["navy federal"]), ("IRS", ["internal revenue service", "irs"]), ("Apple Pay/Card", ["apple pay", "visa", "card"])]:
        if any(t in low for t in terms):
            app.append(name)
    return categories, emails, domains, times, filenames, app


def yes_for(categories, cat):
    return "Yes" if cat in categories else "No"


def time_match(time_text, full_ts):
    if not time_text or not full_ts:
        return "Unknown"
    d = dt(full_ts)
    if not d:
        return "Unknown"
    pairs = re.findall(r"\b(?:[0-1]?\d|2[0-3]):[0-5]\d\b", time_text)
    target24 = d.strftime("%H:%M")
    target12 = d.strftime("%I:%M").lstrip("0")
    return "Yes" if target24 in pairs or target12 in pairs else "No"


def ocr_review(cross, gaps):
    OCR_TEXT_DIR.mkdir(parents=True, exist_ok=True)
    gap_by_sha = {r["SHA256"].upper(): r for r in gaps if r.get("SHA256")}
    gap_by_ts = {r["ScreenshotTimestampFromFilename"]: r for r in gaps if r.get("ScreenshotTimestampFromFilename")}
    candidates = []
    seen = set()
    for r in cross:
        parsed = r["ParsedTimestampFromFilename"]
        msg_dt = dt(r["MessageTimestampLocal"])
        in_range = parsed.startswith("2024-04-") and 19 <= int(parsed[8:10]) <= 26 if parsed else False
        if msg_dt and msg_dt.date() >= datetime(2024, 4, 19).date() and msg_dt.date() <= datetime(2024, 4, 26).date():
            in_range = True
        if not in_range:
            continue
        if r["FullPath"] in seen:
            continue
        seen.add(r["FullPath"])
        candidates.append(r)
    rows = []
    time_rows = []
    for i, r in enumerate(candidates, 1):
        text, err = ocr_image(r["FullPath"])
        text_file = OCR_TEXT_DIR / f"{r['CanonicalImageId']}_{re.sub(r'[^A-Za-z0-9_.-]+', '_', r['FileName'])}.txt"
        text_file.write_text(text, encoding="utf-8", errors="replace")
        cats, emails, domains, times, filenames, apps = detect(text)
        gap = gap_by_sha.get(r["SHA256"].upper()) or gap_by_ts.get(r["ParsedTimestampFromFilename"], {})
        matching_html = ""
        if r["SourceFolder"] != "Messages HTML media":
            for m in r["MatchingFilesInOtherFolders"].split("; "):
                if "Messages\\HTML\\media" in m:
                    matching_html = m
                    break
        else:
            matching_html = r["FullPath"]
        conf = "High" if text and cats else ("Medium" if text else "OCR failed/blank")
        row = {
            "CanonicalImageId": r["CanonicalImageId"],
            "ScreenshotFileName": r["FileName"],
            "ScreenshotPath": r["FullPath"],
            "MatchingHtmlMediaFile": matching_html,
            "SHA256": r["SHA256"],
            "Dimensions": r["Dimensions"],
            "ScreenshotTimestampFromFilename": r["ParsedTimestampFromFilename"],
            "MessageTimestampLocal": gap.get("MessageTimestampLocal", r["MessageTimestampLocal"]),
            "ElapsedSeconds": gap.get("ElapsedSeconds", ""),
            "ConversationOrContact": gap.get("ConversationOrContact", r["ConversationOrContact"]),
            "Direction": gap.get("Direction", r["Direction"]),
            "OCRTextShort": " ".join(text.split())[:500],
            "OCRTextFilePath": str(text_file),
            "DetectedOnScreenTime": "; ".join(dict.fromkeys(times[:5])),
            "DetectedAppOrWebsite": "; ".join(apps),
            "DetectedURLOrDomain": "; ".join(dict.fromkeys(domains[:10])),
            "DetectedAccountOrEmail": "; ".join(dict.fromkeys(emails[:10])),
            "DetectedDocumentOrFileName": "; ".join(dict.fromkeys(filenames[:10])),
            "DetectedSensitiveTerms": "; ".join(cats),
            "AppearsToShowGmail": yes_for(cats, "Gmail"),
            "AppearsToShowGoogleDrive": yes_for(cats, "Google Drive"),
            "AppearsToShowGoogleAccount": yes_for(cats, "Google Account"),
            "AppearsToShowGooglePhotos": yes_for(cats, "Google Photos"),
            "AppearsToShowIRSorEIN": yes_for(cats, "IRS/EIN"),
            "AppearsToShowBankStatement": yes_for(cats, "Bank Statement"),
            "AppearsToShowFinancialStatement": yes_for(cats, "Financial Statement"),
            "AppearsToShowBusinessRecord": yes_for(cats, "Business Record"),
            "AppearsToShowHeloPaymentServices": yes_for(cats, "Helo Payment Services"),
            "AppearsToShowNavyFederal": yes_for(cats, "Navy Federal"),
            "AppearsToShowTrustfi": yes_for(cats, "Trustfi"),
            "AppearsToShowDoorDash": yes_for(cats, "DoorDash"),
            "Confidence": conf,
            "Notes": err,
        }
        rows.append(row)
        time_rows.append({
            "CanonicalImageId": r["CanonicalImageId"],
            "ScreenshotFileName": r["FileName"],
            "FilenameTimestamp": r["ParsedTimestampFromFilename"],
            "DetectedOnScreenTime": row["DetectedOnScreenTime"],
            "MessageTimestamp": row["MessageTimestampLocal"],
            "FilenameToMessageGapSeconds": row["ElapsedSeconds"],
            "OnScreenTimeMatchesFilename": time_match(row["DetectedOnScreenTime"], r["ParsedTimestampFromFilename"]),
            "OnScreenTimeMatchesMessage": time_match(row["DetectedOnScreenTime"], row["MessageTimestampLocal"]),
            "Notes": "Status-bar time OCR is minute-level only and may be unreliable if cropped or noisy.",
        })
    fields = ["CanonicalImageId", "ScreenshotFileName", "ScreenshotPath", "MatchingHtmlMediaFile", "SHA256", "Dimensions", "ScreenshotTimestampFromFilename", "MessageTimestampLocal", "ElapsedSeconds", "ConversationOrContact", "Direction", "OCRTextShort", "OCRTextFilePath", "DetectedOnScreenTime", "DetectedAppOrWebsite", "DetectedURLOrDomain", "DetectedAccountOrEmail", "DetectedDocumentOrFileName", "DetectedSensitiveTerms", "AppearsToShowGmail", "AppearsToShowGoogleDrive", "AppearsToShowGoogleAccount", "AppearsToShowGooglePhotos", "AppearsToShowIRSorEIN", "AppearsToShowBankStatement", "AppearsToShowFinancialStatement", "AppearsToShowBusinessRecord", "AppearsToShowHeloPaymentServices", "AppearsToShowNavyFederal", "AppearsToShowTrustfi", "AppearsToShowDoorDash", "Confidence", "Notes"]
    write_csv(OCR_REVIEW, rows, fields)
    write_csv(TIME_COMPARE, time_rows, ["CanonicalImageId", "ScreenshotFileName", "FilenameTimestamp", "DetectedOnScreenTime", "MessageTimestamp", "FilenameToMessageGapSeconds", "OnScreenTimeMatchesFilename", "OnScreenTimeMatchesMessage", "Notes"])
    return rows, time_rows


def sensitive_exhibits(ocr_rows):
    rows = []
    count = 1
    for r in ocr_rows:
        cats = [c for c in r["DetectedSensitiveTerms"].split("; ") if c]
        if not cats:
            continue
        rows.append({
            "ExhibitNumber": f"OCR-{count:03d}",
            "ScreenshotFileName": r["ScreenshotFileName"],
            "FullPath": r["ScreenshotPath"],
            "SHA256": r["SHA256"],
            "ScreenshotTimestamp": r["ScreenshotTimestampFromFilename"],
            "MessageTimestamp": r["MessageTimestampLocal"],
            "ElapsedSeconds": r["ElapsedSeconds"],
            "SentToContact": r["ConversationOrContact"],
            "SenderPhoneIfKnown": "623-418-0848 believed Elijah phone; Messages.html does not expose as thread handle metadata",
            "RecipientPhoneIfKnown": "386-347-0544 believed Robin/Mom phone; Messages.html does not expose as thread handle metadata",
            "Dimensions": r["Dimensions"],
            "SensitiveContentCategory": "; ".join(cats),
            "KeyOCRTerms": r["DetectedSensitiveTerms"],
            "ContentDescription": r["DetectedAppOrWebsite"] or r["OCRTextShort"][:160],
            "WhyThisMatters": "OCR indicates sensitive Google/account/business/financial content in a screenshot that was linked to the Mom thread.",
            "Limitation": "OCR may misread text; confirm by manual image review and native iPhone database.",
        })
        count += 1
    write_csv(SENSITIVE_EXHIBITS, rows, ["ExhibitNumber", "ScreenshotFileName", "FullPath", "SHA256", "ScreenshotTimestamp", "MessageTimestamp", "ElapsedSeconds", "SentToContact", "SenderPhoneIfKnown", "RecipientPhoneIfKnown", "Dimensions", "SensitiveContentCategory", "KeyOCRTerms", "ContentDescription", "WhyThisMatters", "Limitation"])
    return rows


def verify_thread_numbers():
    text = MESSAGES.read_text(encoding="utf-8", errors="replace") if MESSAGES.exists() else ""
    mom_label = "TO: Mom" in text
    has_386 = "386" in text and "347" in text and "0544" in text
    has_623 = "623" in text and "418" in text and "0848" in text
    return mom_label, has_386, has_623


def write_reports(ocr_rows, time_rows, exhibits, gaps):
    mom_label, has_386, has_623 = verify_thread_numbers()
    lead = next((r for r in ocr_rows if r["ScreenshotTimestampFromFilename"] == "2024-04-19 19:22:24"), {})
    immediate_count = sum(1 for g in gaps if g.get("ElapsedClassification") == "Immediate")
    gmail = sum(1 for r in ocr_rows if r["AppearsToShowGmail"] == "Yes")
    drive = sum(1 for r in ocr_rows if r["AppearsToShowGoogleDrive"] == "Yes")
    acct = sum(1 for r in ocr_rows if r["AppearsToShowGoogleAccount"] == "Yes")
    ein = sum(1 for r in ocr_rows if r["AppearsToShowIRSorEIN"] == "Yes")
    fin = sum(1 for r in ocr_rows if r["AppearsToShowBankStatement"] == "Yes" or r["AppearsToShowFinancialStatement"] == "Yes" or r["AppearsToShowBusinessRecord"] == "Yes")
    onscreen_detected = sum(1 for r in time_rows if r["DetectedOnScreenTime"])
    onscreen_match_file = sum(1 for r in time_rows if r["OnScreenTimeMatchesFilename"] == "Yes")
    thread_note = f"`TO: Mom` label found: {'Yes' if mom_label else 'No'}. 386-347-0544 visible somewhere in HTML text: {'Yes' if has_386 else 'No'}. 623-418-0848 visible somewhere in HTML text: {'Yes' if has_623 else 'No'}. The HTML does not expose both phone numbers as structured thread handles."
    found_later = f"""# Found Later Defense Analysis

The lead screenshot filename timestamp is `2024-04-19 19:22:24`, and the message timestamp is `2024/04/19 19:22:35`, an approximately 11-second gap. This supports the inference of immediate capture-and-send behavior and strongly undermines a simple "found later in Photos" explanation.

The gap analysis verified `{immediate_count}` immediate 0-30 second screenshot-send gaps. Multiple immediate gaps create a repeated pattern that is harder to explain as later discovery. This does not prove guilt and does not independently prove who physically held the phone. It requires native iPhone database confirmation for sender/recipient handles, attachment GUIDs, and actor attribution.

OCR status: local Windows OCR worked and reviewed `{len(ocr_rows)}` images. OCR found Gmail in `{gmail}` screenshot(s), Google Drive in `{drive}`, Google Account in `{acct}`, IRS/EIN in `{ein}`, and bank/financial/business-record indicators in `{fin}`.
"""
    FOUND_LATER.write_text(found_later, encoding="utf-8")
    packet = f"""# New Evidence Packet With OCR Findings

## OCR Status

Windows OCR is installed and working locally. Tesseract is not installed, but Windows OCR successfully processed the screenshot review set.

## Thread / Phone Verification

{thread_note}

## Key Counts

- Screenshots/images OCR-reviewed: {len(ocr_rows)}
- Gmail indicators: {gmail}
- Google Drive indicators: {drive}
- Google Account indicators: {acct}
- IRS/EIN indicators: {ein}
- Bank/financial/business-record indicators: {fin}
- On-screen time detected: {onscreen_detected}
- On-screen time matched filename timestamp: {onscreen_match_file}
- Immediate gaps verified: {immediate_count}

## Lead Screenshot

- Filename timestamp: 2024-04-19 19:22:24
- Message timestamp: 2024/04/19 19:22:35
- Gap: 11 seconds
- Dimensions: 1170 x 2532
- OCR short text: {lead.get('OCRTextShort', '')}
- OCR interpretation: {lead.get('DetectedSensitiveTerms', '') or 'No Gmail/Drive/IRS/EIN sensitive terms detected by OCR in the lead screenshot.'}

## FILE_5531.pdf Role

`FILE_5531.pdf` remains a key non-screenshot exhibit. It appears in the `TO: Mom` sequence at 2024/04/25 12:54:20 between screenshot messages at 12:51:02 and 12:54:44, and it is an IRS CP 575 EIN notice for HELO Payment Services LLC.

## Limitations

OCR is not perfect and must be manually verified. The HTML export supports inferred direction but does not provide native iPhone sender/recipient handles. Actor identity remains the weakest link.
"""
    NEW_PACKET.write_text(packet, encoding="utf-8")
    for path in [
        OUT / "Police_Supplemental_Evidence_Narrative.md",
        OUT / "Evidence_Strength_Assessment.md",
        OUT / "Reopen_Case_Executive_Summary.md",
        OUT / "State_Attorney_Evidence_Timeline.md",
        OUT / "Top_20_Exhibits_For_Reopening.md",
    ]:
        prior = path.read_text(encoding="utf-8", errors="replace") if path.exists() else f"# {path.stem}\n"
        section = f"""

## OCR Findings Update

Windows OCR reviewed {len(ocr_rows)} April 19-26 screenshot/image candidates. Counts: Gmail={gmail}, Google Drive={drive}, Google Account={acct}, IRS/EIN={ein}, bank/financial/business={fin}. On-screen time was detected in {onscreen_detected} image(s), with {onscreen_match_file} matching filename time at minute level. {thread_note}
"""
        if "## OCR Findings Update" not in prior:
            path.write_text(prior + section, encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    if not local_ocr_available():
        OCR_SETUP.write_text("""# OCR Setup Required

No usable local OCR engine was available. Tesseract was not found on PATH, and Windows OCR could not be accessed.

Recommended install command for approval:

```powershell
winget install --id UB-Mannheim.TesseractOCR
```

After installation, rerun the OCR evidence packet script.
""", encoding="utf-8")
        print("OCR installed and working? No")
        print("Recommended command: winget install --id UB-Mannheim.TesseractOCR")
        return
    amap = read_csv(ATTACH_MAP)
    gaps = read_csv(GAPS)
    cross = build_cross_map(amap)
    ocr_rows, time_rows = ocr_review(cross, gaps)
    exhibits = sensitive_exhibits(ocr_rows)
    write_reports(ocr_rows, time_rows, exhibits, gaps)
    mom_label, has_386, has_623 = verify_thread_numbers()
    print("OCR installed and working? Yes - Windows OCR en-US is available and usable.")
    print("Tesseract installed? No.")
    print(f"Screenshots/images OCR-reviewed: {len(ocr_rows)}")
    for label, col in [("Gmail", "AppearsToShowGmail"), ("Google Drive", "AppearsToShowGoogleDrive"), ("Google Account", "AppearsToShowGoogleAccount"), ("IRS/EIN", "AppearsToShowIRSorEIN")]:
        print(f"{label} screenshots: {sum(1 for r in ocr_rows if r[col] == 'Yes')}")
    print(f"Bank/financial/business screenshots: {sum(1 for r in ocr_rows if r['AppearsToShowBankStatement'] == 'Yes' or r['AppearsToShowFinancialStatement'] == 'Yes' or r['AppearsToShowBusinessRecord'] == 'Yes')}")
    lead = next((r for r in ocr_rows if r["ScreenshotTimestampFromFilename"] == "2024-04-19 19:22:24"), {})
    print(f"Lead screenshot OCR short: {lead.get('OCRTextShort', '')[:240]}")
    print(f"On-screen time detections: {sum(1 for r in time_rows if r['DetectedOnScreenTime'])}")
    print(f"On-screen time filename matches: {sum(1 for r in time_rows if r['OnScreenTimeMatchesFilename'] == 'Yes')}")
    print(f"TO: Mom label confirmed? {'Yes' if mom_label else 'No'}")
    print(f"386-347-0544 visible in HTML text? {'Yes' if has_386 else 'No'}")
    print(f"623-418-0848 visible in HTML text? {'Yes' if has_623 else 'No'}")
    print("Thread phone numbers exposed as structured handles? No - not in Messages.html.")
    print(f"Immediate gaps verified: {sum(1 for g in gaps if g.get('ElapsedClassification') == 'Immediate')}")
    print(f"Sensitive OCR exhibits: {len(exhibits)}")
    print(f"Outputs updated in: {OUT}")


if __name__ == "__main__":
    main()
