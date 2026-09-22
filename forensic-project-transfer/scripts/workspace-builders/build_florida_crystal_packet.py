import csv
import html
import json
import shutil
from datetime import datetime
from pathlib import Path


OUT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Florida_Crystal_Well_Steve_Roberge_Evidence")
MEDIA_DIR = OUT_DIR / "media"

UNIQUE_CSV = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet\Unique_Capture_Send_Events.csv")
PHOTOS_CSV = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Google_Photos_Phone_Artifact_Corroboration.csv")
DEVICE_CSV = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Device_Metadata_Audit_Capture_Send_Events.csv")

MESSAGES_HTML = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Messages\HTML\Messages.html")
GBP_DATA = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout\Google Business Profile\account-109822854878924139108\location-7701250605898456430\data.json")
GBP_ADDITIONAL = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout\Google Business Profile\account-109822854878924139108\location-7701250605898456430\additionalData.json")
GBP_ADMIN_STEVE = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout\Google Business Profile\account-109822854878924139108\location-7701250605898456430\locationAdmin-107360321583352836224.json")

TERMS = (
    "florida crystal",
    "roberge",
    "brianna",
    "google business",
    "business profile",
    "google my business",
    "59 brittany",
    "palm coast",
    "steve",
)


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def first(*values):
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def sort_key(row):
    value = first(
        row.get("CaptureTimeEastern"),
        row.get("ScreenshotFilenameTimestamp"),
        row.get("CaptureTimestamp"),
        row.get("MessagesHtmlTextedToMomTimestamp"),
        row.get("TextedTimeEastern"),
    )
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except Exception:
            pass
    return datetime.max


def contains_term(row):
    blob = " ".join(str(v or "") for v in row.values()).lower()
    return any(term in blob for term in TERMS)


def esc(value):
    return html.escape(str(value or ""))


def safe_name(name):
    keep = []
    for ch in name:
        if ch.isalnum() or ch in ("-", "_", "."):
            keep.append(ch)
        elif ch.isspace():
            keep.append("_")
    return "".join(keep)[:180] or "file"


def copy_source_file(path_text, prefix):
    if not path_text:
        return "", "", False
    src = Path(path_text)
    if not src.exists() or not src.is_file():
        return path_text, "", False
    dest_name = f"{prefix}_{safe_name(src.name)}"
    dest = MEDIA_DIR / dest_name
    if not dest.exists():
        shutil.copy2(src, dest)
    return str(src), f"media/{dest.name}", True


def add_hash_path(paths, path_text):
    if path_text:
        p = str(path_text)
        if p not in paths:
            paths.append(p)


def merge_rows():
    unique_rows = {r["CanonicalEventId"]: r for r in read_csv(UNIQUE_CSV)}
    photos_rows = {r["CanonicalEventId"]: r for r in read_csv(PHOTOS_CSV)}
    device_rows = {r["CanonicalEventId"]: r for r in read_csv(DEVICE_CSV)}

    ids = sorted(set(unique_rows) | set(photos_rows) | set(device_rows))
    merged = []
    for ce_id in ids:
        base = {}
        for source, rows in (("unique", unique_rows), ("photos", photos_rows), ("device", device_rows)):
            row = rows.get(ce_id, {})
            for k, v in row.items():
                if v not in (None, ""):
                    base.setdefault(k, v)
            if row:
                base[f"Has_{source}_row"] = "Yes"
        if contains_term(base):
            merged.append(base)

    # Keep this packet narrow. These are the Florida Crystal / Google Business Profile
    # screenshot-message events identified in the existing forensic CSVs.
    merged = [r for r in merged if r.get("CanonicalEventId") in {"CE-005", "CE-006", "CE-007", "CE-008", "CE-009", "CE-010", "CE-015"}]
    merged.sort(key=sort_key)
    return merged


def concise_subject(row):
    ce = row.get("CanonicalEventId")
    if ce == "CE-005":
        return "Google Business Profile message thread with Brianna Tucker and Florida Crystal Well & Sprinkler"
    if ce == "CE-006":
        return "Google Business Profile chat settings showing Florida Crystal Well & Sprinkler as a business"
    if ce == "CE-007":
        return "Florida Crystal customer-message thread involving Ray and Steve Roberge"
    if ce == "CE-008":
        return "Florida Crystal customer-message thread involving Brianna Tucker and Steve Roberge"
    if ce == "CE-009":
        return "Florida Crystal customer/lead message list and business contact records"
    if ce == "CE-010":
        return "Google Business Profile account list showing Florida Crystal Well & Sprinkler"
    if ce == "CE-015":
        return "Gmail message from Google Business Profile about Brianna Tucker contacting Florida Crystal"
    return "Florida Crystal / Google Business Profile screenshot artifact"


def why_it_matters(row):
    ce = row.get("CanonicalEventId")
    if ce in {"CE-007", "CE-008", "CE-009"}:
        return "The recovered image appears to depict customer or lead communications for Florida Crystal Well & Sprinkler, then the message export records it as linked/texted to Mom within seconds."
    if ce == "CE-010":
        return "The recovered image appears to show access to a Google Business Profile account page listing Florida Crystal Well & Sprinkler among managed business profiles."
    if ce == "CE-015":
        return "The recovered image appears to show Gmail content from Google Business Profile about a Florida Crystal customer/lead message."
    return "The recovered image appears to depict Florida Crystal business account or customer-message context and is supported by Google Photos or message-export records."


def limitation(row):
    if row.get("MessagesHtmlTextedToMomTimestamp") or row.get("TextedTimeEastern"):
        return "This supports capture/transmission timing, but does not by itself identify the physical user. Native iPhone Messages/Photos databases and provider logs are needed for final authentication."
    return "This supports capture and Google Photos backup/message-media context, but the texted timestamp was not parsed for this row. Native iPhone records are needed to confirm transfer metadata."


def build_artifacts(rows):
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    processed = []
    for row in rows:
        ce = row.get("CanonicalEventId", "CE")
        paths = []
        add_hash_path(paths, row.get("TimestampedScreenshotFilePath"))
        add_hash_path(paths, row.get("HtmlMediaFilePath"))
        add_hash_path(paths, row.get("PhoneHtmlMediaPath"))
        add_hash_path(paths, row.get("GooglePhotosMediaPath"))
        add_hash_path(paths, row.get("GooglePhotosMetadataPath"))

        image_rel = ""
        copied_sources = []
        for candidate in (
            row.get("HtmlMediaFilePath"),
            row.get("PhoneHtmlMediaPath"),
            row.get("TimestampedScreenshotFilePath"),
            row.get("GooglePhotosMediaPath"),
        ):
            src, rel, copied = copy_source_file(candidate, ce)
            if copied:
                copied_sources.append(src)
                image_rel = image_rel or rel

        row = dict(row)
        row["PacketSubject"] = concise_subject(row)
        row["PacketWhyItMatters"] = why_it_matters(row)
        row["PacketLimitation"] = limitation(row)
        row["PacketImageRelPath"] = image_rel
        row["PacketCopiedSources"] = "; ".join(copied_sources)
        row["PacketAllSourcePaths"] = "; ".join(paths)
        row["ConversationContact"] = row.get("ConversationContact") or "Mom"
        processed.append(row)
    return processed


def source_docs():
    docs = []
    for label, path, note in [
        ("Messages.html export", MESSAGES_HTML, "Message thread export containing media references; native sms.db should confirm final sender/recipient metadata."),
        ("Unique capture/send event table", UNIQUE_CSV, "Existing CE/EX mapping, hashes, screenshot paths, HTML media paths, and parsed texted-to-Mom times."),
        ("Google Photos correlation table", PHOTOS_CSV, "Google Photos backup/sync timing and IOS_PHONE origin records for matched phone artifacts."),
        ("Device metadata audit", DEVICE_CSV, "Image dimensions, DPI, SHA256, and device-dimension assessment."),
        ("Google Business Profile data", GBP_DATA, "Google Takeout business profile source for location 7701250605898456430."),
        ("Google Business Profile additional data", GBP_ADDITIONAL, "Google Takeout source showing 59 Brittany Lane, Palm Coast / Flagler County context."),
        ("Google Business Profile admin record", GBP_ADMIN_STEVE, "Google Takeout source naming Steve Roberge as manager."),
    ]:
        docs.append({"label": label, "path": str(path), "exists": path.exists(), "note": note})
    return docs


def write_csv(rows):
    fieldnames = [
        "CanonicalEventId",
        "PrimaryExhibitNumber",
        "PacketSubject",
        "ScreenshotFilenameTimestamp",
        "CaptureTimeEastern",
        "GooglePhotosTimeEastern",
        "GooglePhotosMinusCaptureSeconds",
        "MessagesHtmlTextedToMomTimestamp",
        "CaptureToTextSeconds",
        "ElapsedSeconds",
        "ConversationContact",
        "PrimarySHA256",
        "MatchClassification",
        "PhoneImageDimensions",
        "PhoneImageDPI",
        "GooglePhotosOrigin",
        "SourceZipFilename",
        "TimestampedScreenshotFilePath",
        "HtmlMediaFilePath",
        "PhoneHtmlMediaPath",
        "GooglePhotosMediaPath",
        "GooglePhotosMetadataPath",
        "PacketImageRelPath",
        "VisualDescription",
        "PacketWhyItMatters",
        "PacketLimitation",
    ]
    with (OUT_DIR / "florida_crystal_evidence_subset.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def render_time(value):
    return esc(value or "not parsed")


def render_card(row, index):
    image = ""
    if row.get("PacketImageRelPath"):
        image = f'<a href="{esc(row["PacketImageRelPath"])}" target="_blank"><img src="{esc(row["PacketImageRelPath"])}" alt="{esc(row.get("CanonicalEventId"))} screenshot"></a>'

    source_detail = ""
    for path in filter(None, row.get("PacketAllSourcePaths", "").split("; ")):
        source_detail += f"<li><code>{esc(path)}</code></li>"

    return f"""
      <article class="card" id="{esc(row.get('CanonicalEventId'))}">
        <div class="card-head">
          <div>
            <div class="eyebrow">Evidence Item {index}</div>
            <h3>{esc(row.get('CanonicalEventId'))} / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))}</h3>
          </div>
          <span class="badge">{esc(row.get('MatchClassification') or 'message/media record')}</span>
        </div>
        <div class="card-grid">
          <div>
            <p class="subject">{esc(row.get('PacketSubject'))}</p>
            <dl class="facts">
              <div><dt>Capture time</dt><dd>{render_time(first(row.get('CaptureTimeEastern'), row.get('ScreenshotFilenameTimestamp'), row.get('CaptureTimestamp')))}</dd></div>
              <div><dt>Google Photos backup</dt><dd>{render_time(row.get('GooglePhotosTimeEastern'))}</dd></div>
              <div><dt>Backup delta</dt><dd>{esc(row.get('GooglePhotosMinusCaptureSeconds') or 'not matched')} seconds</dd></div>
              <div><dt>Texted / linked to Mom</dt><dd>{render_time(first(row.get('MessagesHtmlTextedToMomTimestamp'), row.get('TextedTimeEastern'), row.get('TextedTimestamp')))}</dd></div>
              <div><dt>Capture-to-send</dt><dd>{esc(first(row.get('CaptureToTextSeconds'), row.get('ElapsedSeconds')) or 'not parsed')} seconds</dd></div>
              <div><dt>Conversation</dt><dd>{esc(row.get('ConversationContact') or 'Mom')}</dd></div>
              <div><dt>Phone image data</dt><dd>{esc(first(row.get('PhoneImageDimensions'), row.get('Dimensions')))} / {esc(first(row.get('PhoneImageDPI'), row.get('DPI')))} DPI</dd></div>
              <div><dt>SHA256</dt><dd><code>{esc(row.get('PrimarySHA256') or row.get('SHA256'))}</code></dd></div>
            </dl>
            <p><strong>What records show:</strong> {esc(row.get('PacketWhyItMatters'))}</p>
            <p><strong>Important limitation:</strong> {esc(row.get('PacketLimitation'))}</p>
          </div>
          <figure>{image}<figcaption>{esc(first(row.get('HtmlMediaFileName'), row.get('PhoneHtmlMediaName'), row.get('TimestampedScreenshotFileName'), row.get('GooglePhotosTitle')))}</figcaption></figure>
        </div>
        <details>
          <summary>Show OCR summary and source paths</summary>
          <p class="ocr">{esc(row.get('VisualDescription'))}</p>
          <ul class="sources">{source_detail}</ul>
        </details>
      </article>
    """


def build_html(rows, docs):
    timeline_rows = []
    for row in rows:
        timeline_rows.append(f"""
          <tr>
            <td><a href="#{esc(row.get('CanonicalEventId'))}">{esc(row.get('CanonicalEventId'))}</a></td>
            <td>{esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))}</td>
            <td>{render_time(first(row.get('CaptureTimeEastern'), row.get('ScreenshotFilenameTimestamp'), row.get('CaptureTimestamp')))}</td>
            <td>{render_time(row.get('GooglePhotosTimeEastern'))}</td>
            <td>{render_time(first(row.get('MessagesHtmlTextedToMomTimestamp'), row.get('TextedTimeEastern'), row.get('TextedTimestamp')))}</td>
            <td>{esc(first(row.get('CaptureToTextSeconds'), row.get('ElapsedSeconds')) or 'not parsed')}</td>
            <td>{esc(row.get('PacketSubject'))}</td>
          </tr>
        """)

    source_rows = []
    for doc in docs:
        exists = "Yes" if doc["exists"] else "No"
        source_rows.append(f"""
          <tr>
            <td>{esc(doc['label'])}</td>
            <td>{exists}</td>
            <td><code>{esc(doc['path'])}</code></td>
            <td>{esc(doc['note'])}</td>
          </tr>
        """)

    cards = "\n".join(render_card(row, i + 1) for i, row in enumerate(rows))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Florida Crystal Well & Sprinkler — Business Data Access and Transmission Evidence Packet</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #101317;
      --panel: #171d24;
      --panel2: #202833;
      --ink: #eef3f8;
      --muted: #aab7c4;
      --line: #344150;
      --blue: #78b7ff;
      --green: #7ee39d;
      --gold: #ffd166;
      --red: #ff8a8a;
      --purple: #c9a4ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--ink);
      line-height: 1.55;
    }}
    header {{
      padding: 36px 28px 24px;
      background: linear-gradient(135deg, #152031, #101317 62%);
      border-bottom: 1px solid var(--line);
    }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    h1 {{ margin: 0 0 8px; font-size: clamp(1.7rem, 4vw, 3rem); line-height: 1.08; }}
    h2 {{ margin-top: 30px; color: var(--blue); }}
    h3 {{ margin: 0; font-size: 1.35rem; }}
    .subtitle {{ color: var(--muted); font-size: 1.08rem; }}
    .notice, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      margin: 18px 0;
    }}
    .notice strong {{ color: var(--gold); }}
    nav {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 22px;
    }}
    nav a {{
      color: var(--ink);
      text-decoration: none;
      border: 1px solid var(--line);
      background: #121923;
      padding: 8px 10px;
      border-radius: 7px;
      font-weight: 700;
    }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin: 18px 0;
    }}
    .stat {{
      background: var(--panel2);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
    }}
    .stat b {{ display: block; font-size: 1.75rem; color: var(--green); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: var(--panel);
    }}
    th, td {{
      text-align: left;
      vertical-align: top;
      border-bottom: 1px solid var(--line);
      padding: 10px;
    }}
    th {{ background: #243142; color: var(--ink); }}
    tr:nth-child(even) td {{ background: #151b22; }}
    a {{ color: var(--blue); }}
    code {{
      color: #9be7ff;
      overflow-wrap: anywhere;
      word-break: break-word;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      margin: 18px 0;
      padding: 16px;
    }}
    .card-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 14px;
    }}
    .eyebrow {{
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: .04em;
      font-size: .78rem;
      font-weight: 700;
    }}
    .badge {{
      white-space: nowrap;
      color: #07140d;
      background: var(--green);
      border-radius: 999px;
      padding: 5px 9px;
      font-weight: 800;
      font-size: .82rem;
    }}
    .card-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.55fr) minmax(240px, .95fr);
      gap: 18px;
      align-items: start;
    }}
    figure {{
      margin: 0;
      background: #0c1015;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px;
    }}
    figure img {{
      width: 100%;
      max-height: 520px;
      object-fit: contain;
      display: block;
      border-radius: 4px;
      background: #050607;
    }}
    figcaption {{ color: var(--muted); font-size: .86rem; margin-top: 8px; overflow-wrap: anywhere; }}
    .subject {{ font-size: 1.08rem; color: var(--gold); font-weight: 800; margin-top: 0; }}
    .facts {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 8px;
      margin: 12px 0;
    }}
    .facts div {{
      background: #111820;
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 9px;
    }}
    dt {{ color: var(--muted); font-size: .78rem; text-transform: uppercase; font-weight: 800; }}
    dd {{ margin: 2px 0 0; overflow-wrap: anywhere; }}
    details {{
      margin-top: 12px;
      background: #111820;
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 10px;
    }}
    summary {{ cursor: pointer; font-weight: 800; color: var(--purple); }}
    .ocr {{ color: #d8e2ec; }}
    .sources {{ padding-left: 18px; }}
    .footer {{ color: var(--muted); font-size: .9rem; margin-top: 32px; }}
    @media (max-width: 820px) {{
      main {{ padding: 14px; }}
      header {{ padding: 26px 16px 18px; }}
      .card-grid {{ grid-template-columns: 1fr; }}
      .card-head {{ flex-direction: column; }}
      .badge {{ white-space: normal; }}
      th, td {{ font-size: .9rem; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Florida Crystal Well & Sprinkler — Business Data Access and Transmission Evidence Packet</h1>
    <div class="subtitle">Prepared for review by Flagler County law enforcement</div>
    <nav>
      <a href="#complaint">Independent complaint</a>
      <a href="#bottom-line">Records summary</a>
      <a href="#timeline">Timeline</a>
      <a href="#cards">Evidence cards</a>
      <a href="#sources">Source files</a>
      <a href="#followup">Follow-up</a>
    </nav>
  </header>
  <main>
    <section id="complaint" class="notice">
      <h2>Independent Business-Owner Complaint</h2>
      <p>Steve Roberge is the owner of Florida Crystal Well & Sprinkler, a business operating in Palm Coast, Flagler County, Florida. Thomas Keegan Hurd managed the business’s Google Business Profile / Google My Business account on Steve Roberge’s behalf.</p>
      <p>Steve Roberge states that the customer names, lead communications, account pages, and business information depicted in the attached screenshots belong to Florida Crystal Well & Sprinkler.</p>
      <p>Steve Roberge did not authorize Robin Colleen Hurd-Bedner to access, view, download, capture, screenshot, transmit, or otherwise obtain any Florida Crystal Well & Sprinkler business data.</p>
      <p>Steve Roberge also states that he did not authorize Thomas Keegan Hurd to disclose the business records to any third party except as necessary to manage the Google Business account on behalf of Florida Crystal Well & Sprinkler.</p>
      <p>This packet presents a limited, business-specific subset of evidence for independent review by Flagler County law enforcement.</p>
    </section>

    <section id="bottom-line" class="panel">
      <h2>Records Summary</h2>
      <p>Existing recovered-phone, message-export, Google Photos, and Google Takeout records show a narrow April 25, 2024 sequence involving Florida Crystal Well & Sprinkler business data. The sequence includes screenshots that appear to depict customer/lead messages, Google Business Profile chat/account pages, and a Gmail message from Google Business Profile about Brianna Tucker contacting the business.</p>
      <p>The most direct timing records show captures at 12:28:23 PM, 12:29:02 PM, 12:32:17 PM, 12:33:27 PM, and 12:48:04 PM, followed by message-export “Mom” timestamps within 12 to 29 seconds. Google Photos correlation records show several of the same images backed up to the Google account at the same second or one second after the screenshot capture time, with <code>IOS_PHONE</code> origin metadata and 1170x2532 phone-image dimensions.</p>
      <p>These records support the inference that Florida Crystal business data was displayed, captured, backed up, and transmitted from the phone during this sequence. The records do not by themselves identify the physical user. Native iPhone databases, Apple/iCloud records, and Google provider records should be reviewed to confirm actor identity, message GUIDs, attachment metadata, deletion status, and account-session details.</p>
    </section>

    <section class="panel">
      <h2>Related POPD Case</h2>
      <p>Additional evidence exists involving other accounts that has been provided separately to Port Orange Police Department under Case No. PO250004281.</p>
    </section>

    <section class="panel">
      <h2>Google Business Profile Foundation Records</h2>
      <p>Google Takeout records for Google Business Profile include location <code>7701250605898456430</code>. The available profile data describes a well and sprinkler business operating in the Palm Coast / Flagler County area, and the additional-data record lists <code>59 Brittany Lane, Palm Coast, FL 32137</code>.</p>
      <p>A separate Google Business Profile admin source file names <strong>Steve Roberge</strong> as <code>MANAGER</code> for that location. These records help confirm the business-profile context for the screenshots. They do not by themselves prove who physically used the phone during the screenshot and message sequence.</p>
    </section>

    <section class="stats" aria-label="Packet counts">
      <div class="stat"><b>{len(rows)}</b>Florida Crystal-focused CE items</div>
      <div class="stat"><b>{sum(1 for r in rows if first(r.get('MessagesHtmlTextedToMomTimestamp'), r.get('TextedTimeEastern'), r.get('TextedTimestamp')))}</b>items with parsed texted/linked time</div>
      <div class="stat"><b>{sum(1 for r in rows if r.get('GooglePhotosTimeEastern'))}</b>items with Google Photos timing</div>
      <div class="stat"><b>{sum(1 for r in rows if (r.get('GooglePhotosMinusCaptureSeconds') in ('0', '1')))}</b>items backed up 0-1 sec from capture</div>
    </section>

    <section id="timeline">
      <h2>Chronological Timeline</h2>
      <table>
        <thead>
          <tr><th>CE</th><th>EX</th><th>Capture</th><th>Google Photos backup</th><th>Texted / linked</th><th>Seconds to send</th><th>What it appears to show</th></tr>
        </thead>
        <tbody>{''.join(timeline_rows)}</tbody>
      </table>
    </section>

    <section id="cards">
      <h2>Evidence Cards</h2>
      <p class="notice"><strong>Reading note:</strong> Each card is limited to Florida Crystal Well & Sprinkler / Google Business Profile material. Screenshots are displayed because they are the easiest way for an investigator to see what the recovered artifact appears to depict. Customer information should be treated as business evidence and protected from unnecessary public disclosure.</p>
      {cards}
    </section>

    <section id="sources">
      <h2>Source Files and Traceability</h2>
      <table>
        <thead><tr><th>Source</th><th>Exists</th><th>Path</th><th>Use in this packet</th></tr></thead>
        <tbody>{''.join(source_rows)}</tbody>
      </table>
    </section>

    <section id="followup" class="panel">
      <h2>Recommended Follow-Up Records</h2>
      <p>For authentication, investigators should compare this packet against the native iPhone Messages database (<code>sms.db</code>), attachment table, handle table, Photos database, deletion records, and iCloud/Apple records for April 25, 2024. Google records that would help include Google Account session/device logs, Google Photos upload records, Gmail access logs, and Google Business Profile access/audit logs for the Florida Crystal location.</p>
      <p>Steve Roberge’s written authorization statement should be obtained directly. Google Business Profile provider records should be used to confirm which Google account had management access, what user/session accessed the business profile, and whether customer-message or lead pages were opened during the relevant period.</p>
    </section>

    <p class="footer">Generated locally on {esc(now)}. This packet is a standalone Florida Crystal subset and does not modify the broader POPD evidence packet.</p>
  </main>
</body>
</html>
"""


def write_manifest(rows, docs):
    manifest = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "output_folder": str(OUT_DIR),
        "scope": "Florida Crystal Well & Sprinkler / Steve Roberge business-data subset only",
        "included_ce_ids": [r.get("CanonicalEventId") for r in rows],
        "source_documents": docs,
        "copied_media": [
            {
                "ce": r.get("CanonicalEventId"),
                "relative_path": r.get("PacketImageRelPath"),
                "source_paths": r.get("PacketCopiedSources"),
            }
            for r in rows
        ],
    }
    (OUT_DIR / "packet_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def write_audit(rows, docs):
    lines = [
        "Florida Crystal packet build audit",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Output: {OUT_DIR}",
        "",
        "Included CE IDs:",
    ]
    for row in rows:
        lines.append(f"- {row.get('CanonicalEventId')} / {row.get('PrimaryExhibitNumber') or row.get('Exhibit')}: {row.get('PacketSubject')}")
    lines += ["", "Source documents:"]
    for doc in docs:
        lines.append(f"- {doc['label']}: {'exists' if doc['exists'] else 'missing'} - {doc['path']}")
    lines += [
        "",
        "Limits:",
        "- This packet does not identify the physical user of the phone.",
        "- Native iPhone and provider records are needed to authenticate sender/recipient handles, attachment GUIDs, deletion status, and account session details.",
        "- Customer/lead information should be handled as sensitive business data.",
    ]
    (OUT_DIR / "packet_build_audit.txt").write_text("\n".join(lines), encoding="utf-8")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = build_artifacts(merge_rows())
    docs = source_docs()
    write_csv(rows)
    write_manifest(rows, docs)
    write_audit(rows, docs)
    (OUT_DIR / "index.html").write_text(build_html(rows, docs), encoding="utf-8")
    print(f"Wrote {OUT_DIR / 'index.html'}")
    print(f"Included {len(rows)} evidence rows")
    print(f"Copied media files to {MEDIA_DIR}")


if __name__ == "__main__":
    main()
