import csv
import datetime as dt
import html
import os
import re
import shutil
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import quote


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
CASE = OUT / "Case_Presentation"
IMAGES = CASE / "Images"
TAKEOUT_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
ZIP_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
PHONE_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA")

TIMELINE = OUT / "timeline.csv"
INVENTORY = OUT / "inventory.csv"
INDEXED = OUT / "indexed_files.csv"
EXTRACTION_SUMMARY = OUT / "extraction_summary.csv"
EXTRACTION_ERRORS = OUT / "extraction_errors.csv"
KEYWORD_HITS = OUT / "keyword_hits.csv"
GMAIL_TERMS = OUT / "gmail_common_terms.csv"
PHONE_EVENTS = PHONE_ROOT / "Unique_Capture_Send_Events.csv"
ALIAS_MAP = PHONE_ROOT / "Exhibit_File_Alias_Map.csv"

WINDOW_START = dt.datetime(2024, 4, 19, 0, 0, 0)
WINDOW_END = dt.datetime(2024, 4, 26, 23, 59, 59)

IMPORTANT_TERMS = [
    "helo", "ein", "irs", "cp 575", "bank", "banking", "statement", "merchant",
    "navy federal", "gavin", "jonathan", "ariana", "venmo", "google business",
    "business profile", "drive", "gmail", "gofingerprinting", "fingerprinting",
    "virtue", "docusign", "payanywhere", "authorize.net", "stripe",
]

GMAIL_HIGHLIGHTS = {
    "jonathan", "ariana", "gavin", "venmo", "helo", "ein", "bank",
    "merchant", "gofingerprinting", "go fingerprinting",
}

PHONE_KEYWORDS = [
    "helo", "ein", "irs", "cp 575", "bank", "banking", "statement",
    "navy federal", "gavin", "jonathan", "ariana", "venmo", "google business",
    "business profile", "drive", "gmail", "virtue", "docusign", "florida crystal",
    "financial", "merchant", "file_5531",
]


def read_csv(path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_dt(value):
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def clip(value, limit=260):
    value = re.sub(r"\s+", " ", "" if value is None else str(value)).strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "..."


def file_uri(path):
    p = Path(path)
    return "file:///" + quote(str(p).replace("\\", "/"))


def rel_to_takeout(path):
    try:
        return str(Path(path).relative_to(TAKEOUT_ROOT)).replace("\\", "/")
    except Exception:
        return ""


def build_zip_map():
    mapping = {}
    if not ZIP_ROOT.exists():
        return mapping
    for zp in sorted(ZIP_ROOT.glob("*.zip")):
        try:
            with zipfile.ZipFile(zp) as zf:
                for name in zf.namelist():
                    if name.endswith("/"):
                        continue
                    mapping.setdefault(name, zp.name)
        except Exception:
            continue
    return mapping


def source_zip_for(source_file, zip_map):
    rel = rel_to_takeout(source_file)
    return zip_map.get(rel, "")


def service_class(service, event_type, desc):
    text = f"{service} {event_type} {desc}".lower()
    if "screenshot" in text or "sms" in text:
        return "corr"
    if "searched" in text or "search" in text:
        return "search"
    if "gmail" in text:
        return "gmail"
    if "drive" in text:
        return "drive"
    if "business profile" in text:
        return "business"
    return "other"


def event_score(row):
    text = " ".join(str(v) for v in row.values()).lower()
    score = 0
    for term in IMPORTANT_TERMS:
        if term in text:
            score += 5
    if row.get("Google Service", "").lower() == "gmail":
        score += 8
    if row.get("Event Type", "").lower() == "search":
        score += 5
    if row.get("IP"):
        score += 6
    return score


def phone_score(row):
    text = " ".join(str(v) for v in row.values()).lower()
    score = 0
    for term in PHONE_KEYWORDS:
        if term in text:
            score += 8
    try:
        elapsed = int(float(row.get("ElapsedSeconds") or 9999))
        if elapsed <= 30:
            score += 5
    except Exception:
        pass
    if "file_5531" in text:
        score += 30
    return score


def load_phone_events():
    rows = read_csv(PHONE_EVENTS)
    out = []
    for row in rows:
        ts = parse_dt(row.get("MessagesHtmlTextedToMomTimestamp")) or parse_dt(row.get("ScreenshotFilenameTimestamp"))
        if not ts:
            continue
        row["_dt"] = ts
        row["_score"] = phone_score(row)
        row["_kind"] = "Phone/message artifact"
        out.append(row)
    return sorted(out, key=lambda r: r["_dt"])


def important_phone_events(phone_rows, limit=36):
    selected = []
    for row in sorted(phone_rows, key=lambda r: (-r["_score"], r["_dt"])):
        if row["_score"] <= 0:
            continue
        if row.get("HtmlMediaFilePath") or row.get("TimestampedScreenshotFilePath"):
            selected.append(row)
        if len(selected) >= limit:
            break
    return sorted(selected, key=lambda r: r["_dt"])


def copy_media(rows):
    copied = {}
    IMAGES.mkdir(parents=True, exist_ok=True)
    for row in rows:
        src = row.get("HtmlMediaFilePath") or row.get("TimestampedScreenshotFilePath")
        if not src or not Path(src).exists():
            continue
        suffix = Path(src).suffix.lower() or ".bin"
        base = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"{row.get('CanonicalEventId','event')}_{Path(src).name}")
        dest = IMAGES / base
        try:
            shutil.copy2(src, dest)
            copied[row.get("CanonicalEventId", base)] = dest.name
        except Exception:
            pass
    return copied


def correlate(google_rows, phone_rows):
    out = []
    for grow in google_rows:
        gdt = grow.get("_dt")
        if not gdt:
            continue
        if grow.get("Google Service", "").lower() not in {"gmail", "drive", "google business profile", "search"}:
            continue
        for prow in phone_rows:
            delta = abs((prow["_dt"] - gdt).total_seconds())
            if delta <= 300:
                if delta <= 30:
                    bucket = "Within 30 seconds"
                elif delta <= 60:
                    bucket = "Within 60 seconds"
                else:
                    bucket = "Within 5 minutes"
                out.append({
                    "bucket": bucket,
                    "seconds": int(delta),
                    "google": grow,
                    "phone": prow,
                    "score": event_score(grow) + prow["_score"] + (50 if delta <= 30 else 25 if delta <= 60 else 10),
                })
    out.sort(key=lambda r: (r["google"]["_dt"], r["seconds"]))
    return out


def nav():
    pages = [
        ("01 Executive Summary.html", "Executive Summary"),
        ("02 Timeline.html", "Timeline"),
        ("03 Evidence Gallery.html", "Evidence Gallery"),
        ("04 Search Report.html", "Search Report"),
        ("05 Correlation Report.html", "Correlation Report"),
        ("06 Source Documents.html", "Source Documents"),
        ("07 Findings Summary.html", "Findings Summary"),
    ]
    return '<nav>' + "".join(f'<a href="{esc(h)}">{esc(t)}</a>' for h, t in pages) + "</nav>"


CSS = """
<style>
:root{--ink:#18202a;--muted:#5f6b7a;--line:#d8dde6;--bg:#f6f8fb;--panel:#ffffff;--gmail:#dbeafe;--drive:#dcfce7;--business:#ede9fe;--search:#ffedd5;--corr:#fee2e2;--warn:#fff7cc;}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:18px/1.5 Arial,Helvetica,sans-serif}
header{background:#101827;color:white;padding:28px 36px} header h1{margin:0 0 6px;font-size:34px} header p{margin:0;color:#cbd5e1}
main{max-width:1320px;margin:0 auto;padding:24px 28px 60px}
nav{display:flex;flex-wrap:wrap;gap:8px;background:#e9eef6;padding:10px 28px;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
nav a{background:#fff;border:1px solid var(--line);border-radius:8px;color:#18202a;text-decoration:none;padding:8px 12px;font-weight:700}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin:16px 0;box-shadow:0 1px 2px rgba(15,23,42,.05)}
.summary{font-size:21px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.metric{border-left:8px solid #334155;background:white;padding:14px 16px;border-radius:8px;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.metric b{display:block;font-size:30px}.muted{color:var(--muted)} .small{font-size:14px}.mono{font-family:Consolas,Menlo,monospace}
table{width:100%;border-collapse:collapse;background:white;border:1px solid var(--line);font-size:16px} th{position:sticky;top:57px;background:#1f2937;color:white;text-align:left;padding:10px;z-index:5}td{border-top:1px solid var(--line);padding:10px;vertical-align:top}
tr:nth-child(even){background:#f9fbff}.pill{display:inline-block;border-radius:999px;padding:4px 9px;font-size:13px;font-weight:800;margin:2px;background:#e2e8f0}.gmail{background:var(--gmail)}.drive{background:var(--drive)}.business{background:var(--business)}.search{background:var(--search)}.corr{background:var(--corr)}.important{outline:3px solid #f97316}
.event{border-left:10px solid #94a3b8;padding:14px 16px;margin:12px 0;background:#fff;border-radius:8px;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.event.gmail{border-left-color:#2563eb}.event.drive{border-left-color:#16a34a}.event.business{border-left-color:#7c3aed}.event.search{border-left-color:#f97316}.event.corr{border-left-color:#dc2626}
.time{font-size:22px;font-weight:800}.desc{font-size:18px}.src{font-size:13px;color:#475569;word-break:break-all}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:18px}.shot{background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden}.shot img{width:100%;display:block;background:#111;max-height:520px;object-fit:contain}.shot object{width:100%;height:520px;background:#fff}
.shot .body{padding:14px}.box{border:2px solid #f97316;background:#fff7ed;border-radius:12px;padding:16px;margin:18px 0}.redbox{border-color:#dc2626;background:#fef2f2}.warn{background:var(--warn);border-left:8px solid #f59e0b;padding:14px;border-radius:8px}
@media(max-width:760px){body{font-size:16px}header{padding:22px}main{padding:16px}th{position:static}.gallery{grid-template-columns:1fr}table{font-size:14px}.time{font-size:19px}}
</style>
"""


def html_page(title, subtitle, body):
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(title)}</title>{CSS}</head>
<body><header><h1>{esc(title)}</h1><p>{esc(subtitle)}</p></header>{nav()}<main>{body}</main></body></html>"""


def write(path, content):
    path.write_text(content, encoding="utf-8")


def build_reports():
    CASE.mkdir(parents=True, exist_ok=True)
    IMAGES.mkdir(parents=True, exist_ok=True)

    timeline = read_csv(TIMELINE)
    for row in timeline:
        row["_dt"] = parse_dt(row.get("Timestamp"))
        row["_score"] = event_score(row)
    timeline = [r for r in timeline if r["_dt"]]

    inventory = read_csv(INVENTORY)
    indexed = read_csv(INDEXED)
    extraction = read_csv(EXTRACTION_SUMMARY)
    extraction_errors = read_csv(EXTRACTION_ERRORS)
    phone_rows = load_phone_events()
    selected_phone = important_phone_events(phone_rows)
    copied = copy_media(selected_phone)
    zip_map = build_zip_map()
    correlations = correlate(timeline, phone_rows)

    zip_count = len(extraction) if extraction else len(list(ZIP_ROOT.glob("*.zip")))
    indexed_count = len(indexed)
    inventory_count = len(inventory)
    error_count = len([r for r in extraction_errors if any(r.values())])
    service_counts = Counter(r.get("Google Service", "") for r in timeline)
    gmail_rows = [r for r in timeline if r.get("Google Service", "").lower() == "gmail"]
    gmail_searches = [r for r in gmail_rows if r.get("Event Type", "").lower() == "search"]
    drive_rows = [r for r in timeline if "drive" in r.get("Google Service", "").lower()]
    access_log_rows = read_csv(OUT / "access_log_apr19_26.csv")

    top_google = sorted(timeline, key=lambda r: (-r["_score"], r["_dt"]))[:20]
    top_corr = sorted(correlations, key=lambda r: (-r["score"], r["seconds"]))[:30]
    top_phone = sorted(selected_phone, key=lambda r: (-r["_score"], r["_dt"]))[:20]

    summary_cards = f"""
    <section class="card summary">
      <h2>One-page executive summary for detectives</h2>
      <p>This packet reviews Google Takeout records for <b>April 19, 2024 through April 26, 2024</b> and compares those Google records with independently recovered phone-message artifacts where timing data was available.</p>
      <p>Google's records show Gmail searches and Gmail use during the same week as the recovered screenshot/message sequence. The strongest Google records are Gmail searches for <b>helo payment services ein</b>, <b>Jonathan</b>, <b>Ariana</b>, <b>venmo</b>, and related terms. The phone evidence separately shows screenshot/file transmissions to the conversation labeled <b>Mom</b>, often within seconds of the screenshot filename time.</p>
      <p>This packet does <b>not</b> identify the actor. It does <b>not</b> prove whether access was authorized. It does <b>not</b> provide April 2024 IP addresses or device identifiers from Google's records. It does show objective timestamps, source files, and timing correlations that law enforcement can verify against native device/provider records.</p>
    </section>
    <section class="grid">
      <div class="metric"><b>{zip_count}</b>Takeout ZIP files processed</div>
      <div class="metric"><b>{inventory_count:,}</b>Files inventoried</div>
      <div class="metric"><b>{indexed_count:,}</b>Text/metadata files indexed</div>
      <div class="metric"><b>{len(timeline):,}</b>April 19-26 Google activity rows</div>
      <div class="metric"><b>{len(gmail_rows)}</b>Gmail activity rows</div>
      <div class="metric"><b>{len(gmail_searches)}</b>Gmail search rows</div>
      <div class="metric"><b>{len(drive_rows)}</b>Drive activity rows in timeline</div>
      <div class="metric"><b>{error_count}</b>Extraction errors recorded</div>
    </section>
    <section class="card">
      <h2>Major findings</h2>
      <ul>
        <li>Gmail My Activity contains <b>{len(gmail_rows)}</b> events during the reviewed week.</li>
        <li>Gmail searches recovered include: {esc(', '.join(r['Description'].split('Searched for ')[-1].split(' | ')[0] for r in gmail_searches[:12]))}.</li>
        <li>Access Log Activity is present, but no Access Log Activity rows dated April 19-26, 2024 were recovered in this export.</li>
        <li>Google Account SubscriberInfo contains login-style rows, but the parsed login-style table covers 2025-09-05 through 2026-06-02, not April 2024.</li>
        <li>Recovered phone-message artifacts show a separate capture/send timing pattern, including sensitive business/financial screenshots and FILE_5531.pdf, but actor identity and native message metadata require native records.</li>
      </ul>
    </section>
    <section class="card warn">
      <b>Important limitation:</b> absence of April 2024 IP/device rows in this Takeout is not the same thing as proof that no April 2024 access occurred. It means this export did not provide those fields for that time window.
    </section>
    """
    write(CASE / "01 Executive Summary.html", html_page("01 Executive Summary", "Plain-English overview of the Google Takeout review", summary_cards))

    timeline_items = []
    combined_timeline = []
    for r in timeline:
        combined_timeline.append({"kind": "google", "dt": r["_dt"], "row": r})
    for p in phone_rows:
        combined_timeline.append({"kind": "phone", "dt": p["_dt"], "row": p})
    combined_timeline.sort(key=lambda x: x["dt"])

    for item in combined_timeline:
        if item["kind"] == "phone":
            p = item["row"]
            dtv = item["dt"]
            source = PHONE_EVENTS
            important = " important" if p["_score"] >= 15 else ""
            timeline_items.append(f"""
            <div class="event corr{important}">
              <div class="time">{dtv.strftime('%Y-%m-%d')} &nbsp; {dtv.strftime('%I:%M:%S %p')}</div>
              <div><span class="pill corr">Recovered screenshot/message artifact</span><span class="pill">{esc(p.get('EventType'))}</span></div>
              <p class="desc"><b>{esc(p.get('CanonicalEventId'))} / {esc(p.get('PrimaryExhibitNumber'))}</b>: {esc(clip(p.get('VisualDescription'), 360))}</p>
              <div class="src"><b>Message timestamp:</b> {esc(p.get('MessagesHtmlTextedToMomTimestamp') or 'Not recorded')}<br>
              <b>Screenshot filename timestamp:</b> {esc(p.get('ScreenshotFilenameTimestamp') or 'Not applicable')}<br>
              <b>Source:</b> {esc(str(source))}<br>
              <a href="06 Source Documents.html#{esc(source_id(str(source)))}">Supporting evidence</a></div>
            </div>""")
            continue
        r = item["row"]
        cls = service_class(r.get("Google Service"), r.get("Event Type"), r.get("Description"))
        important = " important" if r["_score"] >= 10 else ""
        source_zip = source_zip_for(r.get("Source File", ""), zip_map)
        dtv = r["_dt"]
        timeline_items.append(f"""
        <div class="event {cls}{important}">
          <div class="time">{dtv.strftime('%Y-%m-%d')} &nbsp; {dtv.strftime('%I:%M:%S %p')}</div>
          <div><span class="pill {cls}">{esc(r.get('Google Service'))}</span><span class="pill">{esc(r.get('Event Type'))}</span></div>
          <p class="desc">{esc(r.get('Description'))}</p>
          <div class="src"><b>Source:</b> {esc(r.get('Source File'))}<br><b>Source ZIP:</b> {esc(source_zip or 'Not mapped / not available')}<br><a href="06 Source Documents.html#{esc(source_id(r.get('Source File')))}">Supporting evidence</a></div>
        </div>""")
    timeline_body = """
    <section class="card"><h2>Color key</h2>
      <span class="pill gmail">Blue = Gmail activity</span>
      <span class="pill drive">Green = Google Drive</span>
      <span class="pill business">Purple = Google Business</span>
      <span class="pill search">Orange = Searches</span>
      <span class="pill corr">Red = Screenshot correlation</span>
    </section>
    """ + "\n".join(timeline_items)
    write(CASE / "02 Timeline.html", html_page("02 Timeline", "Chronological Google activity timeline, April 19-26, 2024", timeline_body))

    gallery_cards = []
    for row in selected_phone:
        ce = row.get("CanonicalEventId", "")
        copied_name = copied.get(ce)
        media = ""
        if copied_name:
            if copied_name.lower().endswith(".pdf"):
                media = f'<object data="Images/{quote(copied_name)}" type="application/pdf"><a href="Images/{quote(copied_name)}">Open PDF</a></object>'
            else:
                media = f'<img src="Images/{quote(copied_name)}" alt="{esc(ce)} supporting screenshot">'
        else:
            media = '<div class="card warn">Media file was not copied or was not found at the recorded path.</div>'
        related = nearest_google(row["_dt"], timeline)
        gallery_cards.append(f"""
        <article class="shot">
          {media}
          <div class="body">
            <h3>{esc(ce)} / {esc(row.get('PrimaryExhibitNumber'))}</h3>
            <p><b>Message timestamp:</b> {esc(row.get('MessagesHtmlTextedToMomTimestamp') or 'Not recorded')}<br>
            <b>Screenshot filename timestamp:</b> {esc(row.get('ScreenshotFilenameTimestamp') or 'Not applicable')}<br>
            <b>Elapsed:</b> {esc(row.get('ElapsedSeconds') or 'Not calculated')} seconds<br>
            <b>Conversation:</b> {esc(row.get('ConversationContact') or 'Not recorded')}</p>
            <p><b>Why relevant:</b> {esc(clip(row.get('WhyItMatters'), 240))}</p>
            <p><b>What it shows:</b> {esc(clip(row.get('VisualDescription'), 320))}</p>
            <p><b>Related Google activity:</b> {esc(related)}</p>
            <p class="src"><b>Recorded source:</b> {esc(row.get('HtmlMediaFilePath') or row.get('TimestampedScreenshotFilePath'))}</p>
          </div>
        </article>""")
    gallery_body = '<section class="gallery">' + "\n".join(gallery_cards) + "</section>"
    write(CASE / "03 Evidence Gallery.html", html_page("03 Evidence Gallery", "Selected phone-message artifacts with copied local media", gallery_body))

    search_rows = []
    for r in gmail_searches:
        term = r["Description"].split("Searched for ")[-1].split(" | ")[0]
        hits = [h for h in GMAIL_HIGHLIGHTS if h in term.lower()]
        cls = " important" if hits else ""
        explain = explain_search(term)
        search_rows.append(f"<tr class='{cls}'><td>{esc(r['_dt'].strftime('%Y-%m-%d %I:%M:%S %p'))}</td><td><b>{esc(term)}</b></td><td>{esc(explain)}</td><td class='src'>{esc(r.get('Source File'))}</td></tr>")
    search_body = f"""
    <section class="card"><p>This page lists every Gmail search recovered from Google My Activity during the reviewed date range. Highlighted rows contain the requested terms or closely related terms.</p></section>
    <table><thead><tr><th>Time</th><th>Search term</th><th>Plain-English explanation</th><th>Source</th></tr></thead><tbody>{''.join(search_rows)}</tbody></table>
    """
    write(CASE / "04 Search Report.html", html_page("04 Search Report", "Recovered Gmail searches from Google My Activity", search_body))

    corr_blocks = []
    grouped = defaultdict(list)
    for c in top_corr:
        grouped[c["bucket"]].append(c)
    for bucket in ["Within 30 seconds", "Within 60 seconds", "Within 5 minutes"]:
        rows = grouped.get(bucket, [])
        if not rows:
            continue
        trs = []
        for c in rows[:35]:
            g, p = c["google"], c["phone"]
            trs.append(f"""
            <tr>
              <td>{esc(bucket)}<br><b>{c['seconds']} sec</b></td>
              <td>{esc(g['_dt'].strftime('%Y-%m-%d %I:%M:%S %p'))}<br>{esc(g.get('Google Service'))}<br>{esc(clip(g.get('Description'), 190))}</td>
              <td>{esc(p['_dt'].strftime('%Y-%m-%d %I:%M:%S %p'))}<br>{esc(p.get('CanonicalEventId'))} / {esc(p.get('PrimaryExhibitNumber'))}<br>{esc(clip(p.get('VisualDescription'), 220))}</td>
              <td>{esc(clip(p.get('Limitation'), 220))}</td>
            </tr>""")
        corr_blocks.append(f"""
        <section class="box {'redbox' if bucket == 'Within 30 seconds' else ''}">
          <h2>{esc(bucket)}</h2>
          <table><thead><tr><th>Window</th><th>Google activity</th><th>Recovered phone/message artifact</th><th>Limitation</th></tr></thead><tbody>{''.join(trs)}</tbody></table>
        </section>""")
    corr_intro = """
    <section class="card summary">
      <p>This report compares Google activity timestamps against recovered screenshot/PDF/message timestamps. A time match does not identify the actor. It shows only that Google's account activity record and the recovered phone artifact occurred close together.</p>
      <p>The strongest correlations are April 26 Gmail searches for Jonathan/Ariana near screenshot transmissions showing those same search terms, and April 25 Gmail activity on the same afternoon as the sensitive screenshot/PDF transmission sequence.</p>
    </section>
    """
    write(CASE / "05 Correlation Report.html", html_page("05 Correlation Report", "Time correlation between Google records and recovered phone/message artifacts", corr_intro + "\n".join(corr_blocks)))

    sources = {}
    for r in timeline:
        sources.setdefault(r.get("Source File", ""), []).append(r)
    source_cards = []
    for src, rows in sorted(sources.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        sid = source_id(src)
        source_zip = source_zip_for(src, zip_map)
        rel = rel_to_takeout(src)
        line_note = "Line number not available from parsed Takeout export; MyActivity HTML records are stored as large HTML blocks." if src.lower().endswith(".html") else "Line number not calculated."
        source_cards.append(f"""
        <section class="card" id="{esc(sid)}">
          <h2>{esc(Path(src).name)}</h2>
          <p><b>Events supported:</b> {len(rows)}<br>
          <b>Exact source file:</b> <span class="mono">{esc(src)}</span><br>
          <b>Relative Takeout path:</b> <span class="mono">{esc(rel or 'Not under Takeout Extracted')}</span><br>
          <b>Original filename:</b> {esc(Path(src).name)}<br>
          <b>ZIP filename:</b> {esc(source_zip or 'Not mapped / not available')}<br>
          <b>Line number:</b> {esc(line_note)}</p>
          <p><a href="{file_uri(src)}">Open local source file</a></p>
        </section>""")
    phone_source_cards = [
        (PHONE_EVENTS, "Recovered phone screenshot/PDF transmission timing table; supports red correlation rows and gallery captions."),
        (ALIAS_MAP, "File alias/hash map for recovered phone media where available."),
    ]
    for src_path, note in phone_source_cards:
        if not src_path.exists():
            continue
        sid = source_id(str(src_path))
        source_cards.append(f"""
        <section class="card" id="{esc(sid)}">
          <h2>{esc(src_path.name)}</h2>
          <p><b>Evidence type:</b> Recovered phone/message export analysis file<br>
          <b>Exact source file:</b> <span class="mono">{esc(str(src_path))}</span><br>
          <b>Relative Takeout path:</b> Not a Google Takeout artifact; independent phone evidence file.<br>
          <b>Original filename:</b> {esc(src_path.name)}<br>
          <b>ZIP filename:</b> Not applicable<br>
          <b>Line number:</b> CSV row numbers correspond to event order; native iPhone database confirmation is still needed.</p>
          <p>{esc(note)}</p>
          <p><a href="{file_uri(src_path)}">Open local source file</a></p>
        </section>""")
    write(CASE / "06 Source Documents.html", html_page("06 Source Documents", "Traceability to original Takeout artifacts", "\n".join(source_cards)))

    findings_body = f"""
    <section class="card summary">
      <h2>What Google's records show</h2>
      <p>Google My Activity records show Gmail searches and Gmail use between April 19 and April 26, 2024. The most relevant searches include HELO/EIN, Jonathan, Ariana, Gavin, Venmo, primecorporatecredit.com, and mlogan@trustfi.com.</p>
      <p>The Takeout also contains Google Business Profile records and Drive files, but the recovered timeline did not contain April 2024 Drive view/download activity rows.</p>
    </section>
    <section class="card summary">
      <h2>What Google's records do not show</h2>
      <p>The Takeout records reviewed here do not show April 2024 IP addresses, device identifiers, session IDs, or a specific actor for the Gmail activity. They also do not show a direct April 2024 Access Log Activity row or a direct Drive download/open record in the timeline.</p>
    </section>
    <section class="card summary">
      <h2>What corroborates independent phone evidence</h2>
      <p>The April 26 Gmail search records for Jonathan and Ariana are close in time and subject matter to recovered screenshot/message artifacts showing those same search terms. The April 25 Gmail activity occurs the same afternoon as recovered phone artifacts showing Gmail/business/financial screenshots and FILE_5531.pdf in the message sequence.</p>
    </section>
    <section class="card summary">
      <h2>What law enforcement could obtain through legal process</h2>
      <p>Provider records could potentially supply missing authentication logs, IP addresses, device/user-agent records, OAuth/session information, Gmail message open/download records, Drive audit/access records, and Apple/iCloud Messages/Photos metadata. Native iPhone records could confirm sender/recipient handles, message GUIDs, attachment GUIDs, deletion status, transfer metadata, and whether the HTML export accurately represents the original message thread.</p>
    </section>
    """
    write(CASE / "07 Findings Summary.html", html_page("07 Findings Summary", "Plain-English findings and limitations", findings_body))

    write(CASE / "presentation_summary.txt", chat_summary(top_google, top_corr, top_phone, zip_count, inventory_count, indexed_count, service_counts, gmail_searches, drive_rows, access_log_rows))


def source_id(src):
    value = re.sub(r"[^A-Za-z0-9]+", "-", src or "source").strip("-")
    return value[-80:] or "source"


def nearest_google(ts, rows):
    best = None
    for r in rows:
        delta = abs((r["_dt"] - ts).total_seconds())
        if best is None or delta < best[0]:
            best = (delta, r)
    if not best:
        return "No Google event parsed."
    delta, r = best
    if delta > 3600:
        return "No parsed Google event within one hour."
    return f"{int(delta)} seconds away: {r.get('Google Service')} - {clip(r.get('Description'), 160)}"


def explain_search(term):
    low = term.lower()
    if "helo" in low or "ein" in low:
        return "Search is directly related to HELO/EIN business records."
    if "jonathan" in low:
        return "Search term matches the April 26 phone screenshot sequence involving Jonathan-related Gmail results."
    if "ariana" in low:
        return "Search term matches the April 26 phone screenshot sequence involving Ariana-related Gmail results."
    if "venmo" in low:
        return "Search relates to payment-transfer records."
    if "gavin" in low:
        return "Search term is specifically recovered in Gmail activity; relevance depends on matching phone/evidence context."
    if "primecorporatecredit" in low or "mlogan" in low:
        return "Search appears related to business/financing email context."
    return "Recovered Gmail search during the reviewed period."


def chat_summary(top_google, top_corr, top_phone, zip_count, inventory_count, indexed_count, service_counts, gmail_searches, drive_rows, access_log_rows):
    lines = []
    lines.append("CASE PRESENTATION SUMMARY\n")
    lines.append("Open first: 01 Executive Summary.html\n")
    lines.append(f"Processed {zip_count} Takeout ZIP files; inventoried {inventory_count:,} files; indexed {indexed_count:,} text/metadata files.\n")
    lines.append("\nTop 20 most significant Google findings:\n")
    for i, r in enumerate(top_google, 1):
        lines.append(f"{i}. {r['_dt']:%Y-%m-%d %I:%M:%S %p} | {r.get('Google Service')} | {r.get('Event Type')} | {clip(r.get('Description'), 160)} | Source: {r.get('Source File')}\n")
    lines.append("\nFive strongest pieces of corroborating evidence:\n")
    for i, c in enumerate(top_corr[:5], 1):
        g, p = c["google"], c["phone"]
        lines.append(f"{i}. {c['bucket']} ({c['seconds']} sec): Google {g.get('Google Service')} at {g['_dt']:%Y-%m-%d %I:%M:%S %p} - {clip(g.get('Description'), 120)}; phone artifact {p.get('CanonicalEventId')} at {p['_dt']:%Y-%m-%d %I:%M:%S %p} - {clip(p.get('VisualDescription'), 120)}.\n")
    lines.append("\nFive most important source files:\n")
    source_counts = Counter(r.get("Source File") for r in top_google)
    for i, (src, count) in enumerate(source_counts.most_common(5), 1):
        lines.append(f"{i}. {src} ({count} top findings)\n")
    lines.append("\nStrongest screenshots / phone artifacts copied into the gallery:\n")
    for i, r in enumerate(top_phone[:10], 1):
        lines.append(f"{i}. {r.get('CanonicalEventId')} / {r.get('PrimaryExhibitNumber')} | {r.get('MessagesHtmlTextedToMomTimestamp')} | {clip(r.get('OCRSensitiveCategory') or r.get('OCRKeyTerms') or r.get('VisualDescription'), 140)}\n")
    lines.append("\nAdditional Takeout ZIPs:\n")
    lines.append("All ZIP files found in the specified Takeout Zips folder were processed. More ZIPs from the same Google export would only matter if additional parts exist outside that folder or if Google/provider legal process supplies logs not included in this Takeout.\n")
    lines.append("\nRecommended additional searches:\n")
    lines.append("Search provider/native records for Gmail message IDs mid=18ee875fe8b9005f and mid=18f00948c0599b31; Drive access/download records for FILE_5531.pdf / HELO Payment Services LLC EIN; Apple/iCloud attachment GUIDs and message transfer metadata; Google Account authentication logs with IP, user agent, and session data for April 19-26, 2024.\n")
    lines.append("\nKey limitations:\n")
    lines.append(f"Access Log Activity rows in target window: {len(access_log_rows)}. Drive activity rows in parsed timeline: {len(drive_rows)}. These records do not identify the actor or determine authorization.\n")
    return "".join(lines)


if __name__ == "__main__":
    build_reports()
    print(f"Created case presentation: {CASE}")
