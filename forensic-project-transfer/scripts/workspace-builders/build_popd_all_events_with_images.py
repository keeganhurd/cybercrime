import csv
import html
import shutil
from pathlib import Path


PACKET_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet")
CSV_PATH = PACKET_DIR / "Unique_Capture_Send_Events.csv"
OUT_DIR = PACKET_DIR / "POPD_All_Events_With_Images"
MEDIA_DIR = OUT_DIR / "media"
OUT_HTML = OUT_DIR / "index.html"


FIELD_ORDER = [
    "CanonicalEventId",
    "EventType",
    "PrimaryExhibitNumber",
    "PrimarySHA256",
    "AllMatchingSHA256sIfAny",
    "ScreenshotFilenameTimestamp",
    "MessagesHtmlTextedToMomTimestamp",
    "ElapsedSeconds",
    "ElapsedClassification",
    "ConversationContact",
    "VisualDescription",
    "RecipientPhoneVisible",
    "SourceDevicePhoneVisible",
    "DirectionInference",
    "TimestampedScreenshotFilePath",
    "TimestampedScreenshotFileName",
    "HtmlMediaFilePath",
    "HtmlMediaFileName",
    "OtherMatchingPaths",
    "CrossFolderMatchStatus",
    "OriginalOrExportDerivativeAssessment",
    "OCRSensitiveCategory",
    "OCRKeyTerms",
    "WhyItMatters",
    "Limitation",
    "NativeConfirmationNeeded",
]


TOP_IDS = [
    "CE-004",
    "CE-017",
    "CE-102",
    "CE-018",
    "CE-020",
    "CE-025",
    "CE-026",
    "CE-029",
    "CE-031",
    "CE-032",
    "CE-035",
    "CE-082",
    "CE-010",
]


def esc(value):
    return html.escape(str(value or ""))


def rel_media(path):
    return "media/" + path.name


def safe_media_name(row, source):
    event_id = row.get("CanonicalEventId") or "event"
    exhibit = row.get("PrimaryExhibitNumber") or "exhibit"
    suffix = source.suffix.lower() or ".bin"
    stem = source.stem
    safe_stem = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in stem)[:90]
    return f"{event_id}_{exhibit}_{safe_stem}{suffix}"


def choose_source(row):
    for key in ("TimestampedScreenshotFilePath", "HtmlMediaFilePath"):
        value = (row.get(key) or "").strip()
        if value:
            p = Path(value)
            if p.exists():
                return p
    return None


def event_sort_key(row):
    return row.get("MessagesHtmlTextedToMomTimestamp") or row.get("ScreenshotFilenameTimestamp") or ""


def pill(value, cls="pill"):
    if not value:
        return '<span class="empty">blank/not shown</span>'
    return f'<span class="{cls}">{esc(value)}</span>'


def field(label, value, cls=""):
    if not value:
        return ""
    return f"""
      <div class="field {cls}">
        <div class="field-label">{esc(label)}</div>
        <div class="field-value">{esc(value)}</div>
      </div>
    """


def media_preview(row):
    copied = row.get("_CopiedMedia", "")
    media_type = row.get("_MediaType", "")
    if not copied:
        return """
        <div class="media-missing">
          <strong>No local preview copied</strong>
          <span>Source file was not found at the path listed in the CSV.</span>
        </div>
        """
    if media_type == "pdf":
        return f"""
        <div class="pdf-preview">
          <object data="{esc(copied)}" type="application/pdf">
            <a href="{esc(copied)}">Open copied PDF</a>
          </object>
          <a class="open-media" href="{esc(copied)}">Open PDF</a>
        </div>
        """
    return f"""
    <a href="{esc(copied)}" class="image-link">
      <img loading="lazy" src="{esc(copied)}" alt="{esc(row.get("CanonicalEventId"))} evidence image">
    </a>
    """


def event_card(row, rank=None, section_prefix=""):
    event_id = row.get("CanonicalEventId", "")
    elapsed = row.get("ElapsedSeconds", "")
    elapsed_cls = "good" if elapsed and elapsed.isdigit() and int(elapsed) <= 30 else "warn"
    categories = row.get("OCRSensitiveCategory", "")
    title = " / ".join(x for x in [event_id, row.get("PrimaryExhibitNumber"), row.get("EventType")] if x)
    rank_html = f'<div class="rank">{esc(section_prefix)}{rank}</div>' if rank else ""
    category_html = f'<div class="category">{esc(categories)}</div>' if categories else ""
    copied = row.get("_CopiedMedia", "")
    return f"""
    <section class="event-card" id="{esc(event_id)}">
      <div class="event-head">
        {rank_html}
        <div>
          <h3>{esc(title)}</h3>
          {category_html}
        </div>
      </div>
      <div class="event-layout">
        <div class="event-text">
          <div class="timeline-strip">
            <div><span>capture</span>{pill(row.get("ScreenshotFilenameTimestamp"), "time capture")}</div>
            <div><span>texted/link</span>{pill(row.get("MessagesHtmlTextedToMomTimestamp"), "time sent")}</div>
            <div><span>elapsed</span>{pill((elapsed + " sec") if elapsed else "", "time " + elapsed_cls)}</div>
            <div><span>contact</span>{pill(row.get("ConversationContact"), "contact")}</div>
          </div>
          <div class="description">{esc(row.get("VisualDescription", ""))}</div>
          <div class="grid">
            {field("File name", row.get("TimestampedScreenshotFileName") or row.get("HtmlMediaFileName"), "file")}
            {field("HTML media file", row.get("HtmlMediaFileName"), "file")}
            {field("Direction inference", row.get("DirectionInference"), "inference")}
            {field("Why it matters", row.get("WhyItMatters"), "why")}
            {field("Limitation", row.get("Limitation"), "limit")}
            {field("Native confirmation needed", row.get("NativeConfirmationNeeded"), "native")}
          </div>
        </div>
        <aside class="media-pane">
          {media_preview(row)}
        </aside>
      </div>
      <details>
        <summary>Expand technical fields and larger media</summary>
        <div class="expanded-media">
          {f'<a href="{esc(copied)}"><img loading="lazy" src="{esc(copied)}" alt="{esc(event_id)} larger preview"></a>' if copied and row.get("_MediaType") == "image" else ""}
          {f'<object data="{esc(copied)}" type="application/pdf"></object>' if copied and row.get("_MediaType") == "pdf" else ""}
        </div>
        <div class="technical">
          {''.join(field(name, row.get(name, ""), "tech") for name in FIELD_ORDER)}
          {field("Copied local media", copied, "file")}
        </div>
      </details>
    </section>
    """


OUT_DIR.mkdir(parents=True, exist_ok=True)
MEDIA_DIR.mkdir(parents=True, exist_ok=True)

with CSV_PATH.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

rows = sorted(rows, key=event_sort_key)

copied_count = 0
missing_count = 0
for row in rows:
    source = choose_source(row)
    if not source:
        row["_CopiedMedia"] = ""
        row["_MediaType"] = ""
        missing_count += 1
        continue
    dest = MEDIA_DIR / safe_media_name(row, source)
    if not dest.exists():
        shutil.copy2(source, dest)
    copied_count += 1
    row["_CopiedMedia"] = rel_media(dest)
    row["_MediaType"] = "pdf" if dest.suffix.lower() == ".pdf" else "image"

by_id = {r.get("CanonicalEventId"): r for r in rows}
top_rows = [by_id[event_id] for event_id in TOP_IDS if event_id in by_id]
remaining_sensitive = [
    r for r in rows
    if r.get("CanonicalEventId") not in TOP_IDS and r.get("OCRSensitiveCategory")
]
top_rows.extend(remaining_sensitive[:12])

immediate = [r for r in rows if (r.get("ElapsedSeconds") or "").isdigit() and int(r["ElapsedSeconds"]) <= 30]
pdf_rows = [r for r in rows if r.get("_MediaType") == "pdf"]

doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>POPD All Events With Images</title>
<style>
  :root {{
    --bg: #f6f7f9;
    --ink: #121417;
    --muted: #5d6673;
    --panel: #ffffff;
    --line: #d7dde5;
    --blue: #dfeeff;
    --blue-ink: #084a83;
    --green: #e3f7ea;
    --green-ink: #116235;
    --amber: #fff0c7;
    --amber-ink: #7a5200;
    --violet: #eee7ff;
    --violet-ink: #54319a;
    --gray: #edf0f4;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font: 15px/1.45 "Segoe UI", Arial, sans-serif;
  }}
  header {{
    position: sticky;
    top: 0;
    z-index: 20;
    background: #17202b;
    color: white;
    padding: 14px 22px;
    border-bottom: 4px solid #6aa6ff;
  }}
  header h1 {{ margin: 0 0 4px; font-size: 22px; }}
  header p {{ margin: 0; color: #d7e5f7; }}
  main {{ max-width: 1380px; margin: 0 auto; padding: 18px; }}
  .summary {{
    display: grid;
    grid-template-columns: repeat(5, minmax(150px, 1fr));
    gap: 10px;
    margin-bottom: 16px;
  }}
  .summary-card {{
    background: var(--panel);
    border: 1px solid var(--line);
    border-left: 7px solid #6aa6ff;
    padding: 12px;
  }}
  .summary-card strong {{ display: block; font-size: 24px; }}
  .note {{
    background: #fff;
    border: 1px solid var(--line);
    border-left: 7px solid #ffbf47;
    padding: 12px 14px;
    margin-bottom: 16px;
  }}
  .note.protect {{
    border-left-color: #43b46f;
    background: #f7fff9;
  }}
  h2 {{
    margin: 24px 0 10px;
    padding-bottom: 6px;
    border-bottom: 2px solid var(--line);
    font-size: 21px;
  }}
  .jump {{
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 10px 0 18px;
  }}
  .jump a {{
    color: #12395f;
    background: #e9f2ff;
    border: 1px solid #b7d5ff;
    border-radius: 5px;
    padding: 5px 8px;
    font-weight: 800;
    text-decoration: none;
  }}
  .event-card {{
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 8px;
    margin: 14px 0;
    overflow: hidden;
    box-shadow: 0 1px 2px rgba(0,0,0,.04);
  }}
  .event-head {{
    display: flex;
    gap: 12px;
    align-items: flex-start;
    background: #f9fbff;
    border-bottom: 1px solid var(--line);
    padding: 12px 14px;
  }}
  .rank {{
    background: #17202b;
    color: #fff;
    font-weight: 700;
    border-radius: 6px;
    padding: 5px 8px;
    min-width: 38px;
    text-align: center;
  }}
  h3 {{ margin: 0; font-size: 18px; }}
  .category {{
    display: inline-block;
    margin-top: 5px;
    padding: 3px 7px;
    background: var(--violet);
    color: var(--violet-ink);
    font-weight: 700;
    border-radius: 5px;
  }}
  .event-layout {{
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
    gap: 0;
  }}
  .event-text {{
    min-width: 0;
    border-right: 1px solid var(--line);
  }}
  .timeline-strip {{
    display: grid;
    grid-template-columns: repeat(4, minmax(140px, 1fr));
    gap: 8px;
    padding: 12px 14px;
    background: #fbfcfe;
    border-bottom: 1px solid var(--line);
  }}
  .timeline-strip span:first-child {{
    display: block;
    text-transform: uppercase;
    color: var(--muted);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: .04em;
    margin-bottom: 4px;
  }}
  .pill, .time, .contact {{
    display: inline-block;
    padding: 3px 7px;
    border-radius: 5px;
    font-weight: 800;
    font-family: Consolas, "Courier New", monospace;
  }}
  .capture {{ background: var(--blue); color: var(--blue-ink); }}
  .sent {{ background: var(--green); color: var(--green-ink); }}
  .good {{ background: var(--green); color: var(--green-ink); }}
  .warn {{ background: var(--amber); color: var(--amber-ink); }}
  .contact {{ background: var(--gray); color: #27313d; }}
  .empty {{ color: var(--muted); font-style: italic; }}
  .description {{
    padding: 12px 14px;
    font-size: 16px;
    background: #fff;
    border-bottom: 1px solid var(--line);
  }}
  .grid {{
    display: grid;
    grid-template-columns: repeat(2, minmax(240px, 1fr));
    gap: 8px;
    padding: 12px 14px;
  }}
  .field {{
    border: 1px solid var(--line);
    background: #fff;
    border-radius: 6px;
    padding: 8px;
    min-width: 0;
  }}
  .field-label {{
    color: var(--muted);
    font-size: 12px;
    font-weight: 800;
    text-transform: uppercase;
    margin-bottom: 3px;
  }}
  .field-value {{ overflow-wrap: anywhere; }}
  .file .field-value {{
    color: #09673b;
    font-family: Consolas, "Courier New", monospace;
    font-weight: 700;
  }}
  .why {{ background: #eef8ff; }}
  .limit {{ background: #fff8e5; }}
  .native {{ background: #f6f0ff; }}
  .media-pane {{
    background: #f1f4f8;
    padding: 12px;
    min-width: 0;
  }}
  .image-link {{
    display: block;
    background: #dfe4eb;
    border: 1px solid #c8d0db;
    border-radius: 7px;
    overflow: hidden;
  }}
  .image-link img {{
    display: block;
    width: 100%;
    max-height: 520px;
    object-fit: contain;
    background: #111;
  }}
  .pdf-preview object {{
    display: block;
    width: 100%;
    height: 520px;
    border: 1px solid #c8d0db;
    background: white;
  }}
  .open-media {{
    display: inline-block;
    margin-top: 8px;
    padding: 6px 9px;
    background: #17202b;
    color: white;
    text-decoration: none;
    border-radius: 5px;
    font-weight: 800;
  }}
  .media-missing {{
    border: 1px dashed #b8c1cc;
    background: white;
    border-radius: 7px;
    padding: 14px;
    color: var(--muted);
  }}
  .media-missing strong {{ display: block; color: #7a5200; margin-bottom: 4px; }}
  details {{
    padding: 0 14px 14px;
    border-top: 1px solid var(--line);
    background: #fff;
  }}
  summary {{
    cursor: pointer;
    color: #245f9f;
    font-weight: 800;
    padding: 12px 0;
  }}
  .expanded-media {{
    margin-bottom: 12px;
  }}
  .expanded-media img {{
    display: block;
    max-width: 100%;
    max-height: 1100px;
    object-fit: contain;
    background: #111;
    border: 1px solid #c8d0db;
    border-radius: 7px;
  }}
  .expanded-media object {{
    width: 100%;
    height: 900px;
    border: 1px solid #c8d0db;
  }}
  .technical {{
    display: grid;
    grid-template-columns: repeat(2, minmax(260px, 1fr));
    gap: 8px;
  }}
  @media (max-width: 980px) {{
    .summary {{ grid-template-columns: repeat(2, 1fr); }}
    .event-layout {{ grid-template-columns: 1fr; }}
    .event-text {{ border-right: 0; border-bottom: 1px solid var(--line); }}
    .timeline-strip, .grid, .technical {{ grid-template-columns: 1fr; }}
  }}
  @media print {{
    header {{ position: static; }}
    body {{ background: white; }}
    .event-card {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<header>
  <h1>POPD All Events With Images</h1>
  <p>One-file review view: forensic timing and copied local media previews in the same card.</p>
</header>
<main>
  <div class="summary">
    <div class="summary-card"><strong>{len(rows)}</strong>Total unique events</div>
    <div class="summary-card"><strong>{len(immediate)}</strong>0-30 second events</div>
    <div class="summary-card"><strong>{len(pdf_rows)}</strong>PDF/document previews</div>
    <div class="summary-card"><strong>{copied_count}</strong>Media files copied</div>
    <div class="summary-card"><strong>{missing_count}</strong>Missing source media</div>
  </div>
  <div class="note protect"><strong>Scope point:</strong> This packet is built to show the difference between ordinary child-phone monitoring and evidence that adult private Google/Gmail/Drive, business, banking, EIN, tax, identity, and financial materials appeared in the Mom message thread shortly after capture.</div>
  <div class="note"><strong>Careful wording:</strong> This HTML does not prove who physically held the phone. It shows source filenames, message-thread timestamps, copied local media, and the timing relationship. Native iPhone Messages records and provider records remain the best confirmation source.</div>
  <h2>Top Probative Events With Media</h2>
  <div class="jump">
    {''.join(f'<a href="#{esc(row.get("CanonicalEventId"))}">{esc(row.get("CanonicalEventId"))}</a>' for row in top_rows)}
  </div>
  {''.join(event_card(row, i + 1, "T") for i, row in enumerate(top_rows))}
  <h2>All Unique Events With Media</h2>
  {''.join(event_card(row, i + 1) for i, row in enumerate(rows))}
</main>
</body>
</html>
"""

OUT_HTML.write_text(doc, encoding="utf-8")
print(f"HTML: {OUT_HTML}")
print(f"Media copied: {copied_count}")
print(f"Missing source media: {missing_count}")
