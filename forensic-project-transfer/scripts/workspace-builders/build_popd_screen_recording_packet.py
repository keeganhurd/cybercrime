import csv
import html
from pathlib import Path


PACKET_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet")
CSV_PATH = PACKET_DIR / "Unique_Capture_Send_Events.csv"
OUT_PATH = PACKET_DIR / "POPD_Screen_Recording_Capture_To_Send_Packet.html"
OUT_ALL_PATH = PACKET_DIR / "POPD_All_Events_Capture_To_Send_Card_Packet.html"


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


TOP_IDS = ["CE-004", "CE-102", "CE-018", "CE-017", "CE-025", "CE-026", "CE-035", "CE-010"]


def esc(value):
    return html.escape(str(value or ""))


def pill(value, cls="pill"):
    if value in (None, ""):
        return '<span class="empty">blank/not shown</span>'
    return f'<span class="{cls}">{esc(value)}</span>'


def event_sort_key(row):
    ts = row.get("MessagesHtmlTextedToMomTimestamp") or row.get("ScreenshotFilenameTimestamp") or ""
    return ts


def display_field(label, value, cls=""):
    if not value:
        return ""
    return f"""
      <div class="field {cls}">
        <div class="field-label">{esc(label)}</div>
        <div class="field-value">{esc(value)}</div>
      </div>
    """


def event_card(row, rank=None):
    event_id = row.get("CanonicalEventId", "")
    categories = row.get("OCRSensitiveCategory", "")
    elapsed = row.get("ElapsedSeconds", "")
    elapsed_cls = "good" if elapsed and elapsed.isdigit() and int(elapsed) <= 30 else "warn"
    title_bits = [event_id]
    if row.get("PrimaryExhibitNumber"):
        title_bits.append(row["PrimaryExhibitNumber"])
    if row.get("EventType"):
        title_bits.append(row["EventType"])
    title = " / ".join(title_bits)
    rank_html = f'<div class="rank">#{rank}</div>' if rank else ""
    category_html = f'<div class="category">{esc(categories)}</div>' if categories else ""
    return f"""
    <section class="event-card" id="{esc(event_id)}">
      <div class="event-head">
        {rank_html}
        <div>
          <h3>{esc(title)}</h3>
          {category_html}
        </div>
      </div>
      <div class="timeline-strip">
        <div><span>capture</span>{pill(row.get("ScreenshotFilenameTimestamp"), "time capture")}</div>
        <div><span>texted/link</span>{pill(row.get("MessagesHtmlTextedToMomTimestamp"), "time sent")}</div>
        <div><span>elapsed</span>{pill((elapsed + " sec") if elapsed else "", "time " + elapsed_cls)}</div>
        <div><span>contact</span>{pill(row.get("ConversationContact"), "contact")}</div>
      </div>
      <div class="description">{esc(row.get("VisualDescription", ""))}</div>
      <div class="grid">
        {display_field("File name", row.get("TimestampedScreenshotFileName") or row.get("HtmlMediaFileName"), "file")}
        {display_field("HTML media file", row.get("HtmlMediaFileName"), "file")}
        {display_field("Direction inference", row.get("DirectionInference"), "inference")}
        {display_field("Why it matters", row.get("WhyItMatters"), "why")}
        {display_field("Limitation", row.get("Limitation"), "limit")}
        {display_field("Native confirmation needed", row.get("NativeConfirmationNeeded"), "native")}
      </div>
      <details>
        <summary>Show full technical fields</summary>
        <div class="technical">
          {''.join(display_field(field, row.get(field, ""), "tech") for field in FIELD_ORDER)}
        </div>
      </details>
    </section>
    """


def table_row(row):
    return f"""
      <tr>
        <td>{esc(row.get("CanonicalEventId"))}</td>
        <td>{esc(row.get("PrimaryExhibitNumber"))}</td>
        <td><span class="time capture">{esc(row.get("ScreenshotFilenameTimestamp"))}</span></td>
        <td><span class="time sent">{esc(row.get("MessagesHtmlTextedToMomTimestamp"))}</span></td>
        <td><span class="time good">{esc(row.get("ElapsedSeconds"))}</span></td>
        <td>{esc(row.get("ConversationContact"))}</td>
        <td>{esc(row.get("VisualDescription"))}</td>
        <td>{esc(row.get("OCRSensitiveCategory"))}</td>
      </tr>
    """


with CSV_PATH.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

rows = sorted(rows, key=event_sort_key)
by_id = {r.get("CanonicalEventId"): r for r in rows}
top_rows = [by_id[i] for i in TOP_IDS if i in by_id]
remaining_sensitive = [
    r for r in rows
    if r.get("CanonicalEventId") not in TOP_IDS and r.get("OCRSensitiveCategory")
]
top_rows.extend(remaining_sensitive[:12])

immediate = [r for r in rows if (r.get("ElapsedSeconds") or "").isdigit() and int(r["ElapsedSeconds"]) <= 30]
pdf_rows = [r for r in rows if r.get("EventType", "").lower().find("pdf") >= 0 or r.get("HtmlMediaFileName", "").lower().endswith(".pdf")]

html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>POPD Capture-to-Send Screen Recording Packet</title>
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
    --rose: #ffe4e9;
    --rose-ink: #8d1730;
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
    z-index: 10;
    background: #17202b;
    color: white;
    padding: 14px 22px;
    border-bottom: 4px solid #6aa6ff;
  }}
  header h1 {{ margin: 0 0 4px; font-size: 22px; }}
  header p {{ margin: 0; color: #d7e5f7; }}
  main {{ max-width: 1220px; margin: 0 auto; padding: 18px; }}
  .summary {{
    display: grid;
    grid-template-columns: repeat(4, minmax(160px, 1fr));
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
  h2 {{
    margin: 24px 0 10px;
    padding-bottom: 6px;
    border-bottom: 2px solid var(--line);
    font-size: 21px;
  }}
  .event-card {{
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 8px;
    margin: 12px 0;
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
  .timeline-strip {{
    display: grid;
    grid-template-columns: repeat(4, minmax(160px, 1fr));
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
  .field-value {{
    overflow-wrap: anywhere;
  }}
  .file .field-value {{
    color: #09673b;
    font-family: Consolas, "Courier New", monospace;
    font-weight: 700;
  }}
  .why {{ background: #eef8ff; }}
  .limit {{ background: #fff8e5; }}
  .native {{ background: #f6f0ff; }}
  details {{
    padding: 0 14px 14px;
  }}
  summary {{
    cursor: pointer;
    color: #245f9f;
    font-weight: 800;
  }}
  .technical {{
    margin-top: 8px;
    display: grid;
    grid-template-columns: repeat(2, minmax(260px, 1fr));
    gap: 8px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
    border: 1px solid var(--line);
  }}
  th {{
    position: sticky;
    top: 66px;
    background: #243244;
    color: white;
    text-align: left;
    padding: 8px;
    font-size: 13px;
  }}
  td {{
    border-top: 1px solid var(--line);
    padding: 7px;
    vertical-align: top;
  }}
  tr:nth-child(even) td {{ background: #fafbfd; }}
  .script {{
    background: #101820;
    color: #ecf3fa;
    border-radius: 8px;
    padding: 14px;
    margin: 10px 0 18px;
  }}
  .script code {{
    color: #d6eaff;
    white-space: pre-wrap;
  }}
  @media print {{
    header, th {{ position: static; }}
    body {{ background: white; }}
    .event-card {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<header>
  <h1>POPD Capture-to-Send Screen Recording Packet</h1>
  <p>Designed for split-screen review with Messages.html on the left and this packet on the right.</p>
</header>
<main>
  <div class="summary">
    <div class="summary-card"><strong>{len(rows)}</strong>Total unique events in CSV</div>
    <div class="summary-card"><strong>{len(immediate)}</strong>Events sent within 0-30 seconds</div>
    <div class="summary-card"><strong>{len(pdf_rows)}</strong>PDF/document event flagged</div>
    <div class="summary-card"><strong>{sum(1 for r in rows if r.get("OCRSensitiveCategory"))}</strong>Events with sensitive categories</div>
  </div>
  <div class="note"><strong>Careful wording for narration:</strong> The export shows screenshots/PDFs appearing in the Mom thread seconds after capture. Exact actor identity, native attachment IDs, and sender/recipient handles still require native iPhone Messages database or provider confirmation.</div>
  <div class="script"><code>Suggested opening: I am showing the Messages.html export on the left and this capture-to-send timeline on the right. The important pattern is the filename capture time, the message-thread timestamp, and the elapsed seconds between capture and transmission.</code></div>
  <h2>Best Events To Show First</h2>
  {''.join(event_card(row, i + 1) for i, row in enumerate(top_rows))}
  <h2>Full Capture-To-Send Table</h2>
  <table>
    <thead>
      <tr>
        <th>Event</th>
        <th>Exhibit</th>
        <th>Capture timestamp</th>
        <th>Texted/link timestamp</th>
        <th>Elapsed</th>
        <th>Contact</th>
        <th>Visual description</th>
        <th>Sensitive category</th>
      </tr>
    </thead>
    <tbody>
      {''.join(table_row(row) for row in rows)}
    </tbody>
  </table>
</main>
</body>
</html>
"""

OUT_PATH.write_text(html_doc, encoding="utf-8")
print(str(OUT_PATH))

all_cards_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>POPD All Events Capture-to-Send Card Packet</title>
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
    z-index: 10;
    background: #17202b;
    color: white;
    padding: 14px 22px;
    border-bottom: 4px solid #6aa6ff;
  }}
  header h1 {{ margin: 0 0 4px; font-size: 22px; }}
  header p {{ margin: 0; color: #d7e5f7; }}
  main {{ max-width: 1220px; margin: 0 auto; padding: 18px; }}
  .summary {{
    display: grid;
    grid-template-columns: repeat(4, minmax(160px, 1fr));
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
  .event-card {{
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 8px;
    margin: 12px 0;
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
  .timeline-strip {{
    display: grid;
    grid-template-columns: repeat(4, minmax(160px, 1fr));
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
  details {{ padding: 0 14px 14px; }}
  summary {{
    cursor: pointer;
    color: #245f9f;
    font-weight: 800;
  }}
  .technical {{
    margin-top: 8px;
    display: grid;
    grid-template-columns: repeat(2, minmax(260px, 1fr));
    gap: 8px;
  }}
  .script {{
    background: #101820;
    color: #ecf3fa;
    border-radius: 8px;
    padding: 14px;
    margin: 10px 0 18px;
  }}
  .script code {{
    color: #d6eaff;
    white-space: pre-wrap;
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
  @media print {{
    header {{ position: static; }}
    body {{ background: white; }}
    .event-card {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<header>
  <h1>POPD All Events Capture-to-Send Card Packet</h1>
  <p>All unique screenshot/PDF events as readable cards, in chronological message-timeline order.</p>
</header>
<main>
  <div class="summary">
    <div class="summary-card"><strong>{len(rows)}</strong>Total unique screenshot/file events</div>
    <div class="summary-card"><strong>{len(immediate)}</strong>Events sent within 0-30 seconds</div>
    <div class="summary-card"><strong>{len(pdf_rows)}</strong>Separate PDF/document event</div>
    <div class="summary-card"><strong>{sum(1 for r in rows if r.get("OCRSensitiveCategory"))}</strong>Events with sensitive categories</div>
  </div>
  <div class="note protect"><strong>Protective relevance:</strong> This packet helps separate ordinary parental monitoring of a child's messages from evidence that the device/message thread may have been used to capture and transmit private adult Google, Gmail, Drive, business, banking, EIN, tax, and identity-related material. It supports a request for native iPhone, Apple/iCloud, Google, and provider confirmation without overstating who physically held the phone.</div>
  <div class="note"><strong>Careful wording:</strong> Say the export shows the files appearing in the Mom thread shortly after capture. Native iPhone Messages records are still needed to confirm original attachment IDs, sender/recipient handles, transfer metadata, deletion status, and actor attribution.</div>
  <div class="script"><code>Suggested narration: This is the full capture-to-send sequence. The blue badge is the screenshot filename capture time. The green badge is the Messages.html texted or linked timestamp. The elapsed badge shows how quickly the screenshot or file appeared in the Mom thread.</code></div>
  <h2>Top Probative Events To Show First</h2>
  <div class="jump">
    {''.join(f'<a href="#{esc(row.get("CanonicalEventId"))}">{esc(row.get("CanonicalEventId"))}</a>' for row in top_rows)}
  </div>
  {''.join(event_card(row, i + 1) for i, row in enumerate(top_rows))}
  <h2>All Unique Events As Video Cards</h2>
  {''.join(event_card(row, i + 1) for i, row in enumerate(rows))}
</main>
</body>
</html>
"""

OUT_ALL_PATH.write_text(all_cards_doc, encoding="utf-8")
print(str(OUT_ALL_PATH))
