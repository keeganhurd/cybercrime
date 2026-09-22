import csv
import datetime as dt
import html
import os
import re
import shutil
import sqlite3
from pathlib import Path
from urllib.parse import quote


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
TAKEOUT_EXTRACTED = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
TAKEOUT_ROOT = TAKEOUT_EXTRACTED / "Takeout"
REQUESTED_HTML = OUT / "index_dark.html"
CURRENT_HTML = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images" / "index_dark.html"
PHONE_EVENTS = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA\Unique_Capture_Send_Events.csv")

DRIVE_MEDIA = OUT / "Drive_Evidence_Media"

START = dt.datetime(2024, 4, 19, 0, 0, 0)
END = dt.datetime(2024, 4, 26, 23, 59, 59)

SEARCH_TERMS = [
    "Drive", "Google Drive", "docs.google.com", "drive.google.com", "doc.google.com",
    "presentation", "spreadsheet", "download", "viewed", "opened", "previewed",
    "searched", "HELO", "EIN", "Navy Federal", "bank", "statement", "merchant",
    "Stripe", "Authorize", "GoFingerprinting", "Helo Payment Services",
    "Jonathan", "Ariana", "Gavin", "Venmo",
]

DRIVE_TERMS = [
    "drive", "google drive", "docs.google.com", "drive.google.com", "doc.google.com",
    "docs", "sheets", "slides", "spreadsheet", "presentation", "pdf",
]

SENSITIVE_TERMS = [
    "helo", "ein", "navy federal", "bank", "statement", "merchant", "stripe",
    "authorize", "gofingerprinting", "helo payment services", "jonathan",
    "ariana", "gavin", "venmo",
]

TEXT_EXTS = {
    ".json", ".html", ".htm", ".csv", ".txt", ".xml", ".mbox", ".log",
    ".sqlite", ".sqlite3", ".db",
}

MONTHS = {
    "Jan": 1, "January": 1, "Feb": 2, "February": 2, "Mar": 3, "March": 3,
    "Apr": 4, "April": 4, "May": 5, "Jun": 6, "June": 6, "Jul": 7, "July": 7,
    "Aug": 8, "August": 8, "Sep": 9, "Sept": 9, "September": 9, "Oct": 10,
    "October": 10, "Nov": 11, "November": 11, "Dec": 12, "December": 12,
}

GOOGLE_DATE_RE = re.compile(
    r"\b("
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|"
    r"Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
    r")\s+(\d{1,2}),\s+(2024),\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)\s*(EDT|EST)?",
    re.I,
)
ISO_RE = re.compile(r"2024-04-(19|20|21|22|23|24|25|26)[T ][0-9:.\-+Z]*", re.I)


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def clean(text):
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text).replace("\u202f", " ").replace("\xa0", " ")
    return re.sub(r"[ \t\r\f\v]+", " ", text).strip()


def clip(text, limit=360):
    text = re.sub(r"\s+", " ", "" if text is None else str(text)).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."


def term_pattern(term):
    low = term.lower()
    if re.fullmatch(r"[a-z0-9]+", low):
        return re.compile(r"(?<![a-z0-9])" + re.escape(low) + r"(?![a-z0-9])", re.I)
    return re.compile(re.escape(term), re.I)


TERM_PATTERNS = [(t, term_pattern(t)) for t in SEARCH_TERMS]


def parse_google_date(text):
    text = text.replace("\u202f", " ").replace("\xa0", " ")
    match = GOOGLE_DATE_RE.search(text)
    if not match:
        return None
    mon, day, year, hour, minute, second, ap, _tz = match.groups()
    hour = int(hour)
    if ap.upper() == "PM" and hour != 12:
        hour += 12
    if ap.upper() == "AM" and hour == 12:
        hour = 0
    return dt.datetime(int(year), MONTHS[mon[:3].title()], int(day), hour, int(minute), int(second))


def parse_any_ts(text):
    ts = parse_google_date(text)
    if ts:
        return ts
    match = ISO_RE.search(text)
    if not match:
        return None
    raw = match.group(0).replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(raw)
        if parsed.tzinfo:
            parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        return None


def parse_dt(value):
    value = (value or "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def rel(path):
    try:
        return str(path.relative_to(TAKEOUT_EXTRACTED)).replace("\\", "/")
    except Exception:
        return str(path)


def service_from_path(path):
    parts = [p.lower() for p in path.parts]
    if "my activity" in parts:
        try:
            return path.parts[parts.index("my activity") + 1]
        except Exception:
            return "My Activity"
    path_text = str(path).lower()
    for service in ["Drive", "Google Account", "Access Log Activity", "Chrome", "Search", "Mail"]:
        if service.lower() in path_text:
            return service
    return "Unknown"


def classify_action(text):
    low = text.lower()
    if "searched for" in low or "searched" in low:
        return "Search"
    if "download" in low:
        return "Download reference"
    if "preview" in low:
        return "Preview reference"
    if "viewed" in low:
        return "Viewed reference"
    if "opened" in low or "visited" in low:
        return "Open/visit reference"
    if "docs.google.com" in low or "drive.google.com" in low:
        return "Google URL reference"
    return "Keyword/context reference"


def has_drive_context(snippet, path, source_service):
    context = (snippet + " " + str(path) + " " + source_service).lower()
    if source_service.lower() in {"drive", "docs", "sheets", "slides"}:
        return True
    return any(term in context for term in DRIVE_TERMS)


def scan_text_file(path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], []
    hits = []
    timeline = []
    low_context = (str(path) + " " + text[:2000]).lower()
    is_google_side = "\\takeout\\" in str(path).lower()
    for term, pattern in TERM_PATTERNS:
        for match in pattern.finditer(text):
            start = max(0, match.start() - 220)
            end = min(len(text), match.end() + 420)
            snippet_raw = text[start:end]
            snippet = clean(snippet_raw)
            ts = parse_any_ts(snippet) or parse_any_ts(text[max(0, match.start() - 5000): match.end() + 5000])
            source_service = service_from_path(path)
            is_drive_related = has_drive_context(snippet, path, source_service)
            hit = {
                "Keyword": term,
                "Timestamp": ts.isoformat(sep=" ", timespec="seconds") if ts else "",
                "SourceService": source_service,
                "SourceFile": str(path),
                "RelativePath": rel(path),
                "IsGoogleSideRecord": "Yes" if is_google_side else "No",
                "IsDriveRelated": "Yes" if is_drive_related else "No",
                "Snippet": clip(snippet, 700),
            }
            hits.append(hit)
            if ts and START <= ts <= END and is_drive_related:
                timeline.append({
                    "Timestamp": ts.isoformat(sep=" ", timespec="seconds"),
                    "EvidenceType": "Google Takeout text/metadata",
                    "Service": source_service,
                    "Action": classify_action(snippet),
                    "Description": clip(snippet, 500),
                    "SourceFile": str(path),
                    "RelativePath": rel(path),
                    "MatchedTerms": term,
                    "Limitation": "Keyword/timestamp context from Takeout file; may not prove file open/download unless source text explicitly says so.",
                })
            break
    return hits, timeline


def scan_sqlite(path):
    hits = []
    timeline = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        cur = conn.cursor()
        tables = cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        for (table,) in tables[:40]:
            try:
                cols = cur.execute(f"PRAGMA table_info({table})").fetchall()
                text_cols = [c[1] for c in cols if "CHAR" in c[2].upper() or "TEXT" in c[2].upper() or not c[2]]
                if not text_cols:
                    continue
                select_cols = ", ".join(f'"{c}"' for c in text_cols[:8])
                for row in cur.execute(f'SELECT {select_cols} FROM "{table}" LIMIT 5000'):
                    blob = " ".join("" if v is None else str(v) for v in row)
                    if not blob:
                        continue
                    terms = [term for term, pat in TERM_PATTERNS if pat.search(blob)]
                    if not terms:
                        continue
                    snippet = clean(blob)
                    ts = parse_any_ts(snippet)
                    is_drive_related = any(d in (snippet + " " + str(path)).lower() for d in DRIVE_TERMS)
                    hits.append({
                        "Keyword": "; ".join(terms),
                        "Timestamp": ts.isoformat(sep=" ", timespec="seconds") if ts else "",
                        "SourceService": service_from_path(path),
                        "SourceFile": str(path),
                        "RelativePath": rel(path),
                        "IsGoogleSideRecord": "Yes",
                        "IsDriveRelated": "Yes" if is_drive_related else "No",
                        "Snippet": clip(f"SQLite table {table}: {snippet}", 700),
                    })
            except Exception:
                continue
        conn.close()
    except Exception:
        pass
    return hits, timeline


def scan_takeout():
    all_hits = []
    timeline = []
    source_files = {}
    for path in TAKEOUT_ROOT.rglob("*"):
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext not in TEXT_EXTS:
            # File names in Drive are still evidence of account contents, but
            # not Google-side access logs.
            path_text = str(path)
            terms = [term for term, pat in TERM_PATTERNS if pat.search(path_text)]
            if terms:
                all_hits.append({
                    "Keyword": "; ".join(terms),
                    "Timestamp": "",
                    "SourceService": service_from_path(path),
                    "SourceFile": str(path),
                    "RelativePath": rel(path),
                    "IsGoogleSideRecord": "Yes",
                "IsDriveRelated": "Yes" if has_drive_context(path_text, path, service_from_path(path)) else "No",
                    "Snippet": f"Filename/path hit only: {path.name}",
                })
            continue
        if ext in {".sqlite", ".sqlite3", ".db"}:
            hits, rows = scan_sqlite(path)
        else:
            hits, rows = scan_text_file(path)
        all_hits.extend(hits)
        timeline.extend(rows)
    return all_hits, timeline


def inspect_expected_sources(all_hits, timeline):
    folders = [
        ("Takeout\\My Activity\\Drive", TAKEOUT_ROOT / "My Activity" / "Drive"),
        ("Takeout\\My Activity\\Docs", TAKEOUT_ROOT / "My Activity" / "Docs"),
        ("Takeout\\My Activity\\Sheets", TAKEOUT_ROOT / "My Activity" / "Sheets"),
        ("Takeout\\My Activity\\Slides", TAKEOUT_ROOT / "My Activity" / "Slides"),
        ("Takeout\\My Activity\\Search", TAKEOUT_ROOT / "My Activity" / "Search"),
        ("Takeout\\Drive", TAKEOUT_ROOT / "Drive"),
        ("Takeout\\Google Account", TAKEOUT_ROOT / "Google Account"),
        ("Takeout\\Access Log Activity", TAKEOUT_ROOT / "Access Log Activity"),
        ("Takeout\\Chrome", TAKEOUT_ROOT / "Chrome"),
        ("Takeout\\Search", TAKEOUT_ROOT / "Search"),
    ]
    rows = []
    for label, folder in folders:
        exists = folder.exists()
        files = [p for p in folder.rglob("*") if p.is_file()] if exists else []
        hits = [h for h in all_hits if h["SourceFile"].lower().startswith(str(folder).lower())] if exists else []
        trows = [t for t in timeline if t["SourceFile"].lower().startswith(str(folder).lower())] if exists else []
        notes = []
        if not exists:
            notes.append("Folder not present in extracted Takeout.")
        elif label.endswith("\\Drive"):
            notes.append("Drive content/export folder; file presence does not by itself prove view/open/download activity.")
        if label.endswith("Access Log Activity") and exists:
            notes.append("Access Log Activity present, but prior parse found no April 19-26, 2024 access-log rows.")
        rows.append({
            "SourceFolder": label,
            "Exists": "Yes" if exists else "No",
            "FileCount": len(files),
            "KeywordHits": len(hits),
            "DriveTimelineRows": len(trows),
            "ExampleFiles": "; ".join(str(p) for p in files[:5]),
            "Notes": " ".join(notes),
        })
    return rows


def load_phone_drive_artifacts():
    if not PHONE_EVENTS.exists():
        return []
    rows = []
    with PHONE_EVENTS.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            text = " ".join([
                row.get("VisualDescription", ""),
                row.get("OCRSensitiveCategory", ""),
                row.get("OCRKeyTerms", ""),
                row.get("HtmlMediaFileName", ""),
                row.get("TimestampedScreenshotFileName", ""),
            ])
            low = text.lower()
            phone_drive_patterns = [
                r"(?<![a-z0-9])drive(?![a-z0-9])",
                r"(?<![a-z0-9])docs?(?![a-z0-9])",
                r"(?<![a-z0-9])sheets?(?![a-z0-9])",
                r"(?<![a-z0-9])slides?(?![a-z0-9])",
                r"google doc",
                r"spreadsheet",
                r"(?<![a-z0-9])pdf(?![a-z0-9])",
                r"file_5531",
            ]
            if any(re.search(pattern, low) for pattern in phone_drive_patterns):
                capture = parse_dt(row.get("ScreenshotFilenameTimestamp"))
                sent = parse_dt(row.get("MessagesHtmlTextedToMomTimestamp"))
                row["_capture"] = capture
                row["_sent"] = sent
                row["_sort"] = sent or capture or dt.datetime.max
                rows.append(row)
    rows.sort(key=lambda r: r["_sort"])
    return rows


def copy_phone_media(rows):
    DRIVE_MEDIA.mkdir(parents=True, exist_ok=True)
    for old in DRIVE_MEDIA.iterdir():
        if old.is_file():
            old.unlink()
    copied = {}
    for row in rows:
        source = row.get("HtmlMediaFilePath") or row.get("TimestampedScreenshotFilePath")
        if not source or not Path(source).exists():
            continue
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{row.get('CanonicalEventId')}_{Path(source).name}")[:190]
        dest = DRIVE_MEDIA / safe
        shutil.copy2(source, dest)
        copied[row.get("CanonicalEventId")] = dest.name
    return copied


def write_csv(path, rows, headers):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def audit_existing_report(phone_drive_rows):
    html_path = REQUESTED_HTML if REQUESTED_HTML.exists() else CURRENT_HTML
    html_text = html_path.read_text(encoding="utf-8", errors="replace") if html_path.exists() else ""
    lower = html_text.lower()
    drive_mentions = lower.count("drive")
    docs_mentions = lower.count("docs.google.com") + lower.count("google doc") + lower.count("sheets")
    google_side_drive = any(phrase in lower for phrase in [
        "google drive records show", "drive activity rows", "my activity\\drive",
        "takeout\\my activity\\drive", "drive file views", "drive downloads",
    ])
    lines = []
    lines.append("# Drive Audit Findings\n\n")
    lines.append(f"Existing report requested: `{REQUESTED_HTML}`\n\n")
    lines.append(f"Existing report actually audited: `{html_path}`\n\n")
    lines.append("## 1. Does the current report include Google Drive logs?\n\n")
    if google_side_drive:
        lines.append("Possibly, but only in limited/general wording. The audit found Drive-related wording in the HTML, but the current integrated report was primarily built around Gmail/My Activity and phone artifact timing.\n\n")
    else:
        lines.append("No clear Google-side Drive activity logs were found in the audited HTML. The report mostly presents Gmail activity plus recovered phone artifacts.\n\n")
    lines.append("## 2. If yes, where?\n\n")
    lines.append(f"The audited HTML contains {drive_mentions} occurrences of the word `Drive` and {docs_mentions} Docs/Sheets-style references. These appear mainly in visible screenshot/OCR content and explanatory labels, not as confirmed Google-side Drive access-log rows.\n\n")
    lines.append("## 3. If no, why not?\n\n")
    lines.append("The prior refined Takeout timeline did not parse April 19-26, 2024 Drive service events. Service counts showed Gmail, Search, Google Business Profile, Maps, YouTube, etc., but no Drive rows in the April 2024 refined timeline.\n\n")
    lines.append("## 4. Are Drive references only coming from screenshots/visible content rather than Google-side records?\n\n")
    lines.append(f"Mostly yes. This audit found {len(phone_drive_rows)} recovered phone artifacts with visible Drive/Docs/Sheets/PDF-style content or filenames. Those are phone/export artifacts, not Google-side Drive access logs.\n\n")
    lines.append("## 5. What source files were searched for Drive evidence?\n\n")
    lines.append("This second-pass audit searched extracted Takeout files under `Takeout`, including My Activity, Drive, Google Account, Access Log Activity, Chrome, Search where present, Mail metadata/MBOX where present, and text-readable JSON/HTML/CSV/TXT/XML/MBOX/LOG/SQLite files.\n\n")
    lines.append("## 6. What source files still need to be searched?\n\n")
    lines.append("If law enforcement needs direct Drive access/open/download proof, the missing sources are provider-side Google Drive audit/access logs, Gmail attachment download/open records, Google Account session/authentication logs for April 19-26, 2024, and native iPhone/iCloud metadata tying screenshots/PDF attachments to the message database.\n")
    return "".join(lines)


CSS = """
<style>
body{margin:0;background:#0e1116;color:#edf2f7;font:16px/1.5 Segoe UI,Arial,sans-serif}
header{background:#0a0d12;border-bottom:4px solid #6aa6ff;padding:18px 24px;position:sticky;top:0}
main{max-width:1280px;margin:0 auto;padding:20px}
h1{margin:0 0 4px;font-size:25px} h2{border-bottom:2px solid #303946;padding-bottom:6px;margin-top:26px}
.card{background:#151b23;border:1px solid #303946;border-radius:8px;padding:14px;margin:12px 0}
.blunt{border-left:8px solid #ffbf47}.found{border-left:8px solid #43b46f}.missing{border-left:8px solid #ff6b6b}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}.metric{background:#101923;border:1px solid #303946;border-left:6px solid #6aa6ff;padding:10px}.metric b{display:block;font-size:26px}
table{width:100%;border-collapse:collapse;background:#151b23;border:1px solid #303946;font-size:14px}th,td{border-top:1px solid #303946;padding:8px;text-align:left;vertical-align:top}th{background:#101923}
.code{font-family:Consolas,monospace;background:#0b0f14;border:1px solid #303946;border-radius:7px;padding:10px;overflow:auto}
.time{color:#78e5aa}.svc{color:#6aa6ff}.act{color:#d7c7ff}.term{color:#ffe2a3}.src{color:#aab4c3;overflow-wrap:anywhere}.red{color:#ff9b9b;font-weight:800}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:14px}.shot{background:#151b23;border:1px solid #303946;border-radius:8px;overflow:hidden}.shot img{width:100%;max-height:520px;object-fit:contain;background:#050608}.shot object{width:100%;height:520px;background:#151b23}.body{padding:12px}
a{color:#9dccff}
</style>
"""


def file_link(path):
    return "file:///" + quote(str(path).replace("\\", "/"))


def media_preview(filename):
    if not filename:
        return '<div class="card missing">No media copied.</div>'
    href = "Drive_Evidence_Media/" + quote(filename)
    if filename.lower().endswith(".pdf"):
        return f'<object data="{href}" type="application/pdf"><a href="{href}">Open PDF</a></object>'
    return f'<a href="{href}"><img src="{href}" alt="Drive related artifact"></a>'


def make_reports(all_hits, timeline, sources, phone_drive_rows, copied):
    status = "B"
    direct_rows = [r for r in timeline if r["Service"].lower() in {"drive", "docs", "sheets", "slides"} or "drive" in r["Description"].lower()]
    if direct_rows:
        status = "A"
    elif not phone_drive_rows:
        status = "C"

    md = []
    md.append("# Google Drive Evidence Report\n\n")
    md.append("## Executive Summary\n\n")
    if status == "A":
        md.append("Drive-related Google Takeout records were found and incorporated. Review the timeline CSV for source paths and snippets.\n\n")
    elif status == "B":
        md.append("Drive-related records were found primarily in recovered screenshots/visible phone artifacts and Drive folder contents, not in direct Google-side April 19-26 Drive access logs.\n\n")
    else:
        md.append("No Drive records were recovered from the current Takeout data.\n\n")
    md.append(f"- Drive keyword hits: {len(all_hits)}\n")
    md.append(f"- Drive timeline rows with April 19-26 timestamps: {len(timeline)}\n")
    md.append(f"- Recovered phone artifacts showing Drive/Docs/Sheets/PDF/file context: {len(phone_drive_rows)}\n\n")
    md.append("## What Google Drive Records Show\n\n")
    if direct_rows:
        for row in direct_rows[:50]:
            md.append(f"- {row['Timestamp']} | {row['Service']} | {row['Action']} | {row['Description']} | Source: `{row['SourceFile']}`\n")
    else:
        md.append("No direct April 19-26, 2024 Google-side Drive open/view/download/search log rows were recovered from the current Takeout parse.\n")
    md.append("\n## What Recovered Screenshots Show\n\n")
    for row in phone_drive_rows[:80]:
        ts = row.get("ScreenshotFilenameTimestamp") or row.get("MessagesHtmlTextedToMomTimestamp")
        md.append(f"- {row.get('CanonicalEventId')} | {ts} | {clip(row.get('VisualDescription'), 260)} | Source: `{row.get('HtmlMediaFilePath') or row.get('TimestampedScreenshotFilePath')}`\n")
    md.append("\n## What Is Missing\n\n")
    md.append("- Direct Google Drive audit rows proving April 2024 view/open/download activity.\n")
    md.append("- April 2024 IP/device/session fields tied to Drive activity.\n")
    md.append("- Native iPhone Messages attachment GUIDs and transfer records tying visible Drive screenshots/PDFs to native message records.\n")
    md.append("\n## What Law Enforcement May Need To Request From Google\n\n")
    md.append("- Google Drive audit/access logs for April 19-26, 2024.\n")
    md.append("- Drive file access/download/preview/open events for HELO/EIN/Navy Federal/business files.\n")
    md.append("- Gmail attachment download/open records for FILE_5531.pdf and related attachments.\n")
    md.append("- Google Account authentication/session logs with IP, user agent, device, and geolocation.\n")
    (OUT / "Drive_Evidence_Report.md").write_text("".join(md), encoding="utf-8")

    gallery = []
    for row in phone_drive_rows:
        ce = row.get("CanonicalEventId")
        gallery.append(f"""
        <section class="shot">
          {media_preview(copied.get(ce))}
          <div class="body">
            <h3>{esc(ce)} / {esc(row.get('PrimaryExhibitNumber'))}</h3>
            <p><b>Capture:</b> {esc(row.get('ScreenshotFilenameTimestamp') or 'N/A')}<br>
            <b>Text/send:</b> {esc(row.get('MessagesHtmlTextedToMomTimestamp') or 'N/A')}<br>
            <b>Elapsed:</b> {esc(row.get('ElapsedSeconds') or 'N/A')} sec</p>
            <p>{esc(clip(row.get('VisualDescription'), 420))}</p>
            <p class="src">{esc(row.get('HtmlMediaFilePath') or row.get('TimestampedScreenshotFilePath'))}</p>
          </div>
        </section>""")
    log_rows = []
    for row in timeline[:200]:
        log_rows.append(f"""
        <div>
          <span class="time">{esc(row['Timestamp'])}</span>
          <span class="svc">{esc(row['Service'])}</span>
          <span class="act">{esc(row['Action'])}</span>
          <span class="term">{esc(row['MatchedTerms'])}</span><br>
          {esc(row['Description'])}<br>
          <span class="src">source: {esc(row['SourceFile'])}</span>
        </div><hr>""")
    source_table = "".join(
        f"<tr><td>{esc(r['SourceFolder'])}</td><td>{esc(r['Exists'])}</td><td>{r['FileCount']}</td><td>{r['KeywordHits']}</td><td>{r['DriveTimelineRows']}</td><td>{esc(r['Notes'])}</td></tr>"
        for r in sources
    )
    html_status = {
        "A": "A. Drive logs were found and incorporated.",
        "B": "B. Drive-related records were found only in screenshots/visible phone artifacts or content/path hits, not direct Google Takeout Drive access logs.",
        "C": "C. No Drive records were recovered from current Takeout data.",
    }[status]
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Drive Evidence Report</title>{CSS}</head><body>
    <header><h1>Google Drive Evidence Report</h1><p>Objective Drive-focused audit of Google Takeout and recovered phone artifacts.</p></header>
    <main>
      <section class="card {'found' if status == 'A' else 'blunt' if status == 'B' else 'missing'}"><h2>Executive Summary</h2><p><b>{esc(html_status)}</b></p><p>This does not identify the physical user and does not determine authorization.</p></section>
      <section class="grid">
        <div class="metric"><b>{len(all_hits)}</b>Drive keyword/context hits</div>
        <div class="metric"><b>{len(timeline)}</b>April 19-26 Drive timeline rows</div>
        <div class="metric"><b>{len(phone_drive_rows)}</b>Drive/Docs/PDF phone artifacts</div>
        <div class="metric"><b>{len(direct_rows)}</b>direct Google-side Drive-like rows</div>
      </section>
      <h2>What Google Drive Records Show</h2>
      <div class="card"><p>{'Direct Drive-like Google-side rows were found below.' if direct_rows else 'No direct April 19-26, 2024 Google-side Drive open/view/download/search log rows were recovered from this Takeout parse.'}</p></div>
      <div class="code">{''.join(log_rows) if log_rows else '<span class="red">No Drive timeline rows recovered.</span>'}</div>
      <h2>What Recovered Screenshots Show</h2>
      <div class="gallery">{''.join(gallery)}</div>
      <h2>Source Coverage</h2>
      <table><thead><tr><th>Folder</th><th>Exists</th><th>Files</th><th>Hits</th><th>Timeline rows</th><th>Notes</th></tr></thead><tbody>{source_table}</tbody></table>
      <h2>What Is Missing</h2>
      <section class="card missing"><ul><li>Direct Drive audit rows proving April 2024 view/open/download activity.</li><li>April 2024 IP/device/session data tied to Drive.</li><li>Native iPhone message attachment metadata.</li></ul></section>
      <h2>What Law Enforcement May Need To Request From Google</h2>
      <section class="card"><ul><li>Drive audit/access logs for April 19-26, 2024.</li><li>Drive file open/preview/download events for HELO/EIN/Navy Federal/business records.</li><li>Gmail attachment download/open records for FILE_5531.pdf.</li><li>Authentication/session logs with IP, user agent, device, and location.</li></ul></section>
    </main></body></html>"""
    (OUT / "Drive_Evidence_Report.html").write_text(html_doc, encoding="utf-8")
    return status, html_status, direct_rows


def update_main_html(status_text, direct_count, phone_count):
    source = REQUESTED_HTML if REQUESTED_HTML.exists() else CURRENT_HTML
    if not source.exists():
        base = "<!doctype html><html><head><meta charset='utf-8'><title>Drive Audit</title></head><body><main></main></body></html>"
    else:
        base = source.read_text(encoding="utf-8", errors="replace")
    section = f"""
    <section class="note protect" id="google-drive-evidence-status">
      <strong>Google Drive Evidence Status:</strong> {esc(status_text)}<br>
      Direct Google-side Drive-like rows found: {direct_count}. Recovered phone artifacts showing Drive/Docs/PDF/file context: {phone_count}.<br>
      <a href="Drive_Evidence_Report.html">Open Drive Evidence Report</a>
    </section>
    """
    if "<main>" in base:
        updated = base.replace("<main>", "<main>\n" + section, 1)
    else:
        updated = section + base
    (OUT / "index_dark_with_drive_audit.html").write_text(updated, encoding="utf-8")


def main():
    DRIVE_MEDIA.mkdir(parents=True, exist_ok=True)
    all_hits, timeline = scan_takeout()
    timeline.sort(key=lambda r: r["Timestamp"])
    phone_drive_rows = load_phone_drive_artifacts()
    copied = copy_phone_media(phone_drive_rows)
    sources = inspect_expected_sources(all_hits, timeline)

    write_csv(OUT / "Drive_Keyword_Hits.csv", all_hits, ["Keyword", "Timestamp", "SourceService", "SourceFile", "RelativePath", "IsGoogleSideRecord", "IsDriveRelated", "Snippet"])
    write_csv(OUT / "Drive_Activity_Timeline.csv", timeline, ["Timestamp", "EvidenceType", "Service", "Action", "Description", "SourceFile", "RelativePath", "MatchedTerms", "Limitation"])
    write_csv(OUT / "Drive_Source_Files.csv", sources, ["SourceFolder", "Exists", "FileCount", "KeywordHits", "DriveTimelineRows", "ExampleFiles", "Notes"])
    (OUT / "Drive_Audit_Findings.md").write_text(audit_existing_report(phone_drive_rows), encoding="utf-8")
    status, status_text, direct_rows = make_reports(all_hits, timeline, sources, phone_drive_rows, copied)
    update_main_html(status_text, len(direct_rows), len(phone_drive_rows))
    print(f"Drive audit status: {status_text}")
    print(f"Drive keyword hits: {len(all_hits)}")
    print(f"Drive timeline rows: {len(timeline)}")
    print(f"Phone Drive/Docs/PDF artifacts: {len(phone_drive_rows)}")
    print(f"Outputs written to: {OUT}")


if __name__ == "__main__":
    main()
