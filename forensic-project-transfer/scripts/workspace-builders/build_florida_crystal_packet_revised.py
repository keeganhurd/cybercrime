import csv
import html
import json
import re
import shutil
from datetime import datetime
from pathlib import Path


OUT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Florida_Crystal_Well_Steve_Roberge_Evidence")
MEDIA_DIR = OUT_DIR / "media"

UNIQUE_CSV = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet\Unique_Capture_Send_Events.csv")
PHOTOS_CSV = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Google_Photos_Phone_Artifact_Corroboration.csv")
DEVICE_CSV = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Device_Metadata_Audit_Capture_Send_Events.csv")
SUBSET_CSV = OUT_DIR / "florida_crystal_evidence_subset.csv"

MESSAGES_HTML = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Messages\HTML\Messages.html")
GBP_DATA = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout\Google Business Profile\account-109822854878924139108\location-7701250605898456430\data.json")
GBP_ADDITIONAL = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout\Google Business Profile\account-109822854878924139108\location-7701250605898456430\additionalData.json")
GBP_ADMIN_STEVE = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout\Google Business Profile\account-109822854878924139108\location-7701250605898456430\locationAdmin-107360321583352836224.json")

CE_IDS = ["CE-005", "CE-006", "CE-007", "CE-008", "CE-009", "CE-010", "CE-015"]
TIER1 = ["CE-008", "CE-015", "CE-007"]
TIER2 = ["CE-009", "CE-010"]
TIER3 = ["CE-005", "CE-006"]
RECIPIENT = "386-347-0544"


SUBJECTS = {
    "CE-005": "Brianna Tucker / Florida Crystal Well & Sprinkler message screen",
    "CE-006": "Google Business Profile chat settings showing Florida Crystal",
    "CE-007": "Customer message involving Ray and Steve Roberge",
    "CE-008": "Brianna Tucker message for Florida Crystal Well & Sprinkler",
    "CE-009": "Florida Crystal customer/lead message list",
    "CE-010": "Google Business Profile account list showing Florida Crystal",
    "CE-015": "Gmail notification from Google Business Profile about Brianna Tucker",
}


def read_csv(path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def esc(value):
    return html.escape(str(value or ""))


def first(*values):
    for value in values:
        if value not in (None, ""):
            return value
    return ""


def clean_display(text):
    text = str(text or "")
    replacements = {
        "ΓÇ»": " ",
        "â€¯": " ",
        "â€™": "'",
        "â€œ": '"',
        "â€": '"',
        "â€”": "-",
        "Î“Ã‡Â»": " ",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def display_filename(path_or_name):
    name = Path(path_or_name).name if path_or_name else ""
    return clean_display(name)


def abbreviated_hash(value):
    value = str(value or "")
    if len(value) <= 24:
        return value
    return f"{value[:10]}...{value[-10:]}"


def parse_time(value):
    value = str(value or "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def display_time(value):
    dt = parse_time(value)
    if not dt:
        return "not parsed"
    hour = dt.strftime("%I").lstrip("0")
    return f"{dt.strftime('%Y-%m-%d')} {hour}:{dt.strftime('%M:%S %p')}"


def display_clock(value):
    dt = parse_time(value)
    if not dt:
        return "not parsed"
    hour = dt.strftime("%I").lstrip("0")
    return f"{hour}:{dt.strftime('%M:%S %p')}"


def sort_key(row):
    return parse_time(capture_time(row)) or datetime.max


def capture_time(row):
    return first(row.get("CaptureTimeEastern"), row.get("ScreenshotFilenameTimestamp"), row.get("CaptureTimestamp"))


def transmission_time(row):
    return first(row.get("MessagesHtmlTextedToMomTimestamp"), row.get("TextedTimeEastern"), row.get("TextedTimestamp"))


def transmission_delta(row):
    return first(row.get("CaptureToTextSeconds"), row.get("ElapsedSeconds"))


def backup_delta(row):
    return row.get("GooglePhotosMinusCaptureSeconds") or "not matched"


def backup_badge(row):
    delta = backup_delta(row)
    if delta in ("0", "1"):
        return f"{delta}-SECOND BACKUP"
    return "BACKUP NOT MATCHED"


def transmission_badge(row):
    delta = transmission_delta(row)
    if delta:
        return f"{delta}-SECOND TRANSMISSION"
    return "TRANSMISSION TIME NOT PARSED"


def merge_rows():
    unique = {r["CanonicalEventId"]: r for r in read_csv(UNIQUE_CSV)}
    photos = {r["CanonicalEventId"]: r for r in read_csv(PHOTOS_CSV)}
    device = {r["CanonicalEventId"]: r for r in read_csv(DEVICE_CSV)}
    subset = {r["CanonicalEventId"]: r for r in read_csv(SUBSET_CSV)}

    rows = []
    for ce in CE_IDS:
        merged = {}
        for source_name, source_rows in (
            ("unique", unique),
            ("photos", photos),
            ("device", device),
            ("subset", subset),
        ):
            row = source_rows.get(ce, {})
            if row:
                merged[f"Has_{source_name}_row"] = "Yes"
            for key, value in row.items():
                if value not in (None, ""):
                    merged.setdefault(key, value)
        merged["CanonicalEventId"] = ce
        merged["PacketSubject"] = SUBJECTS.get(ce, "Florida Crystal evidence item")
        merged["RecipientForDisplay"] = RECIPIENT
        if not merged.get("PacketImageRelPath"):
            for candidate in ("PhoneHtmlMediaPath", "HtmlMediaFilePath", "TimestampedScreenshotFilePath", "GooglePhotosMediaPath"):
                p = merged.get(candidate)
                if p and Path(p).exists():
                    # The original packet generator already copied media into media/ with CE prefix.
                    candidates = sorted(MEDIA_DIR.glob(f"{ce}_*"))
                    image = next((c for c in candidates if c.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp"}), None)
                    if image:
                        merged["PacketImageRelPath"] = f"media/{image.name}"
                    break
        make_revised_media_copy(merged)
        rows.append(merged)
    rows.sort(key=sort_key)
    return rows


def make_revised_media_copy(row):
    rel = row.get("PacketImageRelPath")
    if not rel:
        return
    src = OUT_DIR / rel
    if not src.exists():
        return
    ce = row.get("CanonicalEventId", "CE")
    clean_name = f"{ce}_{main_filename(row)}"
    clean_name = re.sub(r"[^A-Za-z0-9_. -]+", "", clean_name).strip().replace(" ", "_")
    if not clean_name.lower().endswith(src.suffix.lower()):
        clean_name += src.suffix
    dest = MEDIA_DIR / clean_name
    if not dest.exists():
        shutil.copy2(src, dest)
    row["RevisedImageRelPath"] = f"media/{dest.name}"
    row["RevisedImageSourceOriginalRelPath"] = rel


def main_filename(row):
    for key in ("PhoneHtmlMediaName", "HtmlMediaFileName", "TimestampedScreenshotFileName", "FileName", "GooglePhotosTitle"):
        if row.get(key):
            return display_filename(row[key])
    path = first(row.get("PhoneHtmlMediaPath"), row.get("HtmlMediaFilePath"), row.get("TimestampedScreenshotFilePath"), row.get("GooglePhotosMediaPath"))
    return display_filename(path)


def source_paths(row):
    keys = [
        "TimestampedScreenshotFilePath",
        "HtmlMediaFilePath",
        "PhoneHtmlMediaPath",
        "GooglePhotosMediaPath",
        "GooglePhotosMetadataPath",
        "ImagePathScanned",
    ]
    paths = []
    for key in keys:
        value = row.get(key)
        if value and value not in paths:
            paths.append(value)
    return paths


def google_photos_sentence(row):
    delta = backup_delta(row)
    if delta in ("0", "1"):
        return "The matched Google Photos record shows backup/sync at the same second or one second after screenshot capture. This strongly supports fresh capture on a device logged into or syncing with the Google account associated with keeganhurd@gmail.com and is inconsistent with a later manual upload of an old screenshot."
    return "The current Google Photos row does not provide a complete same-second backup match for this item. Native device and provider records should be used for final confirmation."


def timeline_row(row):
    emphasis = " class=\"tier1-row\"" if row["CanonicalEventId"] in {"CE-008", "CE-015"} else ""
    tx = transmission_time(row)
    return f"""
      <tr{emphasis}>
        <td><a href="#{esc(row['CanonicalEventId'])}"><span class="technical-value">{esc(row['CanonicalEventId'])}</span> / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))}</a></td>
        <td><span class="entity-value">{esc(row['PacketSubject'])}</span></td>
        <td><span class="capture-value">{esc(display_time(capture_time(row)))}</span></td>
        <td><span class="backup-value">{esc(display_time(row.get('GooglePhotosTimeEastern')))}</span></td>
        <td><span class="delta-value">{esc(backup_delta(row))}</span></td>
        <td><span class="transmit-value">{esc(display_time(tx)) if tx else 'not parsed'}</span></td>
        <td><span class="delta-value">{esc(transmission_delta(row) or 'not parsed')}</span></td>
      </tr>
    """


def image_block(row, large=False):
    rel = row.get("RevisedImageRelPath") or row.get("PacketImageRelPath")
    if not rel:
        return '<div class="missing-image">Image copy not found in packet media folder.</div>'
    cls = "evidence-image large" if large else "evidence-image"
    return f'<a href="{esc(rel)}" target="_blank"><img class="{cls}" src="{esc(rel)}" alt="{esc(row["CanonicalEventId"])} screenshot"></a>'


def fact_badges(row):
    return f"""
      <div class="badges">
        <span>{esc(backup_badge(row))}</span>
        <span>{esc(transmission_badge(row))}</span>
      </div>
    """


def timing_bar(row):
    tx = transmission_time(row)
    return f"""
      <div class="flow">
        <div><b>CAPTURE</b><span class="capture-value">{esc(display_clock(capture_time(row)))}</span></div>
        <div class="arrow">-&gt;</div>
        <div><b>GOOGLE PHOTOS BACKUP</b><span class="backup-value">{esc(display_clock(row.get('GooglePhotosTimeEastern')))}</span></div>
        <div class="arrow">-&gt;</div>
        <div><b>TRANSMISSION</b><span class="transmit-value">{esc(display_clock(tx)) if tx else 'not parsed'}</span></div>
      </div>
    """


def compact_file_meta(row):
    sha = first(row.get("PrimarySHA256"), row.get("SHA256"))
    return f"""
      <dl class="mini-meta">
        <div><dt>Evidence ID</dt><dd><span class="technical-value">{esc(row['CanonicalEventId'])}</span> / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))}</dd></div>
        <div><dt>Filename</dt><dd>{esc(main_filename(row))}</dd></div>
        <div><dt>SHA-256</dt><dd><span class="technical-value">{esc(abbreviated_hash(sha))}</span></dd></div>
        <div><dt>Recipient</dt><dd><span class="transmit-value">{RECIPIENT}</span></dd></div>
      </dl>
      <p class="muted-note">Full source and hash in Appendix B.</p>
    """


def full_card(row, ordinal):
    return f"""
    <article class="card full" id="{esc(row['CanonicalEventId'])}">
      <div class="card-head">
        <div>
          <div class="tier">Tier 1 Evidence Item {ordinal}</div>
          <h3>{esc(row['CanonicalEventId'])} / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))} - <span class="entity-value">{esc(row['PacketSubject'])}</span></h3>
        </div>
        {fact_badges(row)}
      </div>
      {timing_bar(row)}
      <div class="evidence-layout">
        <div>
          {compact_file_meta(row)}
          <p>{esc(google_photos_sentence(row))}</p>
          <p class="operator-note">Actor identity should be evaluated with native phone/provider records, the recipient association, phone-control evidence, and recorded statements.</p>
        </div>
        <figure>{image_block(row)}<figcaption>{esc(main_filename(row))}</figcaption></figure>
      </div>
    </article>
    """


def condensed_card(row):
    return f"""
    <article class="card condensed" id="{esc(row['CanonicalEventId'])}">
      <div class="thumb">{image_block(row)}</div>
      <div>
        <div class="tier">Tier 2 Supporting Evidence</div>
        <h3>{esc(row['CanonicalEventId'])} / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))}</h3>
        <p><span class="entity-value">{esc(row['PacketSubject'])}</span></p>
        {fact_badges(row)}
        {timing_bar(row)}
        <p>Recipient: <span class="transmit-value">{RECIPIENT}</span></p>
        <p class="muted-note">Full source and hash in Appendix B.</p>
      </div>
    </article>
    """


def tier3_table(rows_by_id):
    body = []
    for ce in TIER3:
        row = rows_by_id[ce]
        body.append(f"""
          <tr>
            <td><span class="technical-value">{esc(ce)}</span> / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))}</td>
            <td><span class="entity-value">{esc(row['PacketSubject'])}</span></td>
            <td><span class="capture-value">{esc(display_time(capture_time(row)))}</span></td>
            <td><span class="backup-value">{esc(display_time(row.get('GooglePhotosTimeEastern')))}</span></td>
            <td><span class="delta-value">{esc(backup_delta(row))}</span></td>
            <td>{esc(main_filename(row))}</td>
          </tr>
        """)
    return f"""
    <table>
      <thead><tr><th>Evidence ID</th><th>Visible content</th><th>Screenshot capture</th><th>Google Photos backup</th><th>Backup delta</th><th>Display filename</th></tr></thead>
      <tbody>{''.join(body)}</tbody>
    </table>
    <p class="muted-note">These items independently show matching Florida Crystal business content and 0-1 second Google Photos backup timing. The recipient-transmission timestamp was not parsed in the current export and should be confirmed through native device records.</p>
    """


def appendix_b(rows):
    blocks = []
    for row in rows:
        paths = "".join(f"<li><code>{esc(p)}</code></li>" for p in source_paths(row))
        blocks.append(f"""
          <details>
            <summary>{esc(row['CanonicalEventId'])} / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))} - source files and hashes</summary>
            <dl class="appendix-meta">
              <div><dt>Full SHA-256</dt><dd><code>{esc(first(row.get('PrimarySHA256'), row.get('SHA256')))}</code></dd></div>
              <div><dt>Original display filename</dt><dd>{esc(main_filename(row))}</dd></div>
              <div><dt>Recipient-number source</dt><dd>{esc(row.get('RecipientPhoneVisible'))}</dd></div>
              <div><dt>Source-device text</dt><dd>{esc(row.get('SourceDevicePhoneVisible'))}</dd></div>
              <div><dt>Direction inference</dt><dd>{esc(row.get('DirectionInference'))}</dd></div>
              <div><dt>Google Photos origin</dt><dd><code>{esc(row.get('GooglePhotosOrigin'))}</code></dd></div>
              <div><dt>Phone image dimensions / DPI</dt><dd>{esc(first(row.get('PhoneImageDimensions'), row.get('Dimensions')))} / {esc(first(row.get('PhoneImageDPI'), row.get('DPI')))}</dd></div>
            </dl>
            <ul>{paths}</ul>
          </details>
        """)
    return "\n".join(blocks)


def appendix_c(rows):
    blocks = []
    for row in rows:
        blocks.append(f"""
          <details>
            <summary>{esc(row['CanonicalEventId'])} / {esc(row.get('PrimaryExhibitNumber') or row.get('Exhibit'))} - OCR and audit trail</summary>
            <p>{esc(clean_display(row.get('VisualDescription')))}</p>
            <p class="muted-note">Matched source rows: Unique capture/send={esc(row.get('Has_unique_row'))}; Google Photos correlation={esc(row.get('Has_photos_row'))}; Device metadata={esc(row.get('Has_device_row'))}; Prior subset={esc(row.get('Has_subset_row'))}.</p>
          </details>
        """)
    return "\n".join(blocks)


def build_html(rows):
    rows_by_id = {r["CanonicalEventId"]: r for r in rows}
    chronological = sorted(rows, key=sort_key)
    strongest = rows_by_id["CE-008"]
    ce015 = rows_by_id["CE-015"]
    ce007 = rows_by_id["CE-007"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Florida Crystal Well & Sprinkler - Unauthorized Business Data Access Evidence</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0f1117;
      --panel: #171b23;
      --panel2: #1f2530;
      --ink: #eef3f8;
      --line: #313b4a;
      --capture: #ff9e64;
      --backup: #9ece6a;
      --transmit: #7dcfff;
      --delta: #e0af68;
      --account: #bb9af7;
      --entity: #f6c177;
      --technical: #73daca;
      --muted-note: #8b98a8;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.48; }}
    header {{ padding: 30px 24px 20px; border-bottom: 1px solid var(--line); background: #121722; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 20px; }}
    h1 {{ margin: 0; font-size: clamp(1.8rem, 4vw, 3rem); line-height: 1.08; }}
    h2 {{ margin-top: 28px; color: var(--transmit); }}
    h3 {{ margin: 0 0 8px; }}
    .subtitle {{ margin-top: 8px; color: var(--entity); font-weight: 800; font-size: 1.12rem; }}
    .prepared {{ color: var(--muted-note); margin-top: 5px; }}
    nav {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }}
    nav a {{ color: var(--ink); text-decoration: none; border: 1px solid var(--line); background: #1a2130; padding: 7px 9px; border-radius: 6px; font-weight: 700; }}
    section, .card, .box {{ background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin: 16px 0; }}
    .first-page {{ border-left: 4px solid var(--entity); }}
    .chain-focus {{ border: 2px solid var(--backup); background: #141b20; }}
    .capture-value {{ color: var(--capture); font-weight: 800; }}
    .backup-value {{ color: var(--backup); font-weight: 800; }}
    .transmit-value {{ color: var(--transmit); font-weight: 800; }}
    .delta-value {{ color: var(--delta); font-weight: 900; }}
    .account-value {{ color: var(--account); font-weight: 800; }}
    .entity-value {{ color: var(--entity); font-weight: 800; }}
    .technical-value {{ color: var(--technical); }}
    .muted-note {{ color: var(--muted-note); }}
    .flow {{ display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; gap: 10px; align-items: center; margin: 14px 0; }}
    .flow div:not(.arrow) {{ background: #111722; border: 1px solid var(--line); border-radius: 8px; padding: 11px; min-height: 70px; }}
    .flow b {{ display: block; color: var(--muted-note); font-size: .8rem; letter-spacing: .04em; }}
    .arrow {{ color: var(--delta); font-weight: 900; font-size: 1.4rem; }}
    .hero-grid, .evidence-layout {{ display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(320px, .85fr); gap: 16px; align-items: start; }}
    img.evidence-image {{ width: 100%; max-height: 520px; object-fit: contain; border-radius: 6px; background: #05070a; border: 1px solid var(--line); }}
    img.large {{ max-height: 620px; }}
    figure {{ margin: 0; }}
    figcaption {{ color: var(--muted-note); font-size: .86rem; margin-top: 6px; overflow-wrap: anywhere; }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .badges span {{ background: #202b24; border: 1px solid #3e6747; color: var(--backup); padding: 5px 8px; border-radius: 999px; font-weight: 900; font-size: .78rem; }}
    .mini-meta, .appendix-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; margin: 12px 0; }}
    .mini-meta div, .appendix-meta div {{ background: #111722; border: 1px solid var(--line); border-radius: 7px; padding: 8px; }}
    dt {{ color: var(--muted-note); font-size: .75rem; text-transform: uppercase; font-weight: 900; }}
    dd {{ margin: 2px 0 0; overflow-wrap: anywhere; }}
    table {{ width: 100%; border-collapse: collapse; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: var(--panel); }}
    th, td {{ padding: 9px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); }}
    th {{ background: #202838; }}
    tr:nth-child(even) td {{ background: #141922; }}
    .tier1-row td {{ border-top: 1px solid var(--entity); border-bottom: 1px solid var(--entity); background: #1a1b1f !important; }}
    .tier {{ color: var(--muted-note); text-transform: uppercase; letter-spacing: .04em; font-weight: 900; font-size: .78rem; }}
    .condensed {{ display: grid; grid-template-columns: 170px 1fr; gap: 14px; }}
    .thumb img {{ max-height: 220px; }}
    details {{ background: #111722; border: 1px solid var(--line); border-radius: 7px; padding: 10px; margin: 8px 0; }}
    summary {{ color: var(--entity); cursor: pointer; font-weight: 900; }}
    code {{ color: var(--technical); overflow-wrap: anywhere; word-break: break-word; }}
    .request li {{ margin: 6px 0; }}
    .draft {{ border: 1px solid var(--delta); background: #211c12; color: var(--delta); display: inline-block; padding: 4px 8px; border-radius: 6px; font-weight: 900; }}
    @media print {{
      :root {{ color-scheme: light; }}
      body {{ background: #fff; color: #111; }}
      section, .card, .box {{ break-inside: avoid; border-color: #999; background: #fff; }}
      nav {{ display: none; }}
    }}
    @media (max-width: 850px) {{
      main {{ padding: 12px; }}
      header {{ padding: 22px 14px; }}
      .hero-grid, .evidence-layout, .condensed {{ grid-template-columns: 1fr; }}
      .flow {{ grid-template-columns: 1fr; }}
      .arrow {{ text-align: center; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Florida Crystal Well & Sprinkler - Unauthorized Business Data Access Evidence</h1>
    <div class="subtitle">Business-owner identification, capture timing, Google Photos account-linked backup, and transmission evidence</div>
    <div class="prepared">Prepared for Flagler County law-enforcement review</div>
    <nav>
      <a href="#first-page">30-second summary</a>
      <a href="#timeline">Timeline</a>
      <a href="#tier1">Tier 1</a>
      <a href="#tier2">Tier 2</a>
      <a href="#tier3">Tier 3</a>
      <a href="#followup">Follow-up</a>
      <a href="#appendix-a">Appendix A</a>
      <a href="#appendix-b">Appendix B</a>
      <a href="#appendix-c">Appendix C</a>
      <a href="#appendix-d">Appendix D</a>
    </nav>
  </header>
  <main>
    <section id="first-page" class="first-page">
      <h2>Ownership and Lack of Authorization</h2>
      <p><span class="entity-value">Steve Roberge</span> owns <span class="entity-value">Florida Crystal Well & Sprinkler</span> in Palm Coast, Flagler County, Florida. Thomas Keegan Hurd was authorized to manage the business's Google Business Profile through the Google account associated with <span class="account-value">keeganhurd@gmail.com</span>. Steve Roberge identifies the customer communications, lead information, account pages, and business records shown in this packet as Florida Crystal Well & Sprinkler business data.</p>
      <p>Steve Roberge did not authorize Robin Colleen Hurd-Bedner to access, view, capture, screenshot, download, transmit, or otherwise obtain this business data. Thomas Keegan Hurd did not authorize Robin Colleen Hurd-Bedner or any other unauthorized person to access or capture the data.</p>
    </section>

    <section class="chain-focus" id="CE-008">
      <h2>Strongest Evidence Chain: CE-008 / EX-065</h2>
      <div class="hero-grid">
        <div>
          <h3><span class="entity-value">Brianna Tucker / Florida Crystal Well & Sprinkler</span></h3>
          <p><span class="capture-value">12:29:02 PM</span> - Screenshot captured</p>
          <p><span class="backup-value">12:29:02 PM</span> - Google Photos backup/sync for the Google account associated with <span class="account-value">keeganhurd@gmail.com</span></p>
          <p><span class="transmit-value">12:29:14 PM</span> - Transmitted to <span class="transmit-value">{RECIPIENT}</span></p>
          <p>Capture-to-transmission delta: <span class="delta-value">12 seconds</span></p>
          <p>Capture-to-backup delta: <span class="delta-value">0 seconds</span></p>
          {timing_bar(strongest)}
          <p class="muted-note">The recovered message export labels this contact as "Mom." The associated recipient telephone number is 386-347-0544. The packet uses the telephone number because it is the relevant forensic identifier.</p>
        </div>
        <figure>{image_block(strongest, large=True)}<figcaption>{esc(main_filename(strongest))}</figcaption></figure>
      </div>
    </section>

    <section>
      <h2>Central Evidence Conclusion</h2>
      <p>Florida Crystal Well & Sprinkler customer and business-account data was freshly captured from Google-linked business interfaces, backed up through Google Photos for the Google account associated with keeganhurd@gmail.com within 0-1 second, and transmitted to 386-347-0544 within seconds. The timing strongly supports live display or access to account-linked content on a device logged into or syncing with that Google account. Steve Roberge identifies the information as his business data and states that Robin Colleen Hurd-Bedner was not authorized to access, capture, or transmit it.</p>
    </section>

    <section class="box">
      <h2>Related Investigation</h2>
      <p>Port Orange Police Department Case No. <span class="technical-value">PO250004281</span><br>
      Broader dataset: approximately <span class="technical-value">102</span> recovered digital artifacts<br>
      POPD reviewed data recovered from the relevant phone<br>
      POPD obtained a recorded statement from Robin Colleen Hurd-Bedner<br>
      This packet is limited to the seven Florida Crystal Well & Sprinkler items</p>
    </section>

    <section class="box">
      <h2>Request for Investigation</h2>
      <p>Steve Roberge respectfully requests that Flagler County law enforcement independently review this evidence and determine whether further investigation, coordination with POPD, preservation requests, provider records, device records, or additional interviews are appropriate.</p>
    </section>

    <section id="timeline">
      <h2>Complete Chronological Timeline of Seven Items</h2>
      <table>
        <thead><tr><th>Evidence ID</th><th>Visible content</th><th>Screenshot capture</th><th>Google Photos backup</th><th>Backup delta</th><th>Transmission to {RECIPIENT}</th><th>Capture-to-transmission delta</th></tr></thead>
        <tbody>{''.join(timeline_row(r) for r in chronological)}</tbody>
      </table>
    </section>

    <section id="tier1">
      <h2>Tier 1 Evidence Items</h2>
      {full_card(strongest, 1)}
      {full_card(ce015, 2)}
      {full_card(ce007, 3)}
    </section>

    <section id="tier2">
      <h2>Tier 2 Supporting Evidence</h2>
      {''.join(condensed_card(rows_by_id[ce]) for ce in TIER2)}
    </section>

    <section id="tier3">
      <h2>Tier 3 Corroborating Items</h2>
      {tier3_table(rows_by_id)}
    </section>

    <section>
      <h2>Evidence Boundary</h2>
      <p>The timing and account-linked records establish a fresh capture, backup, and transmission sequence. They do not alone identify the person physically operating the device. Actor identification should be evaluated from the total evidence, including device possession and control, the recipient telephone number, native iPhone records, Apple/iCloud records, Google account and Google Business Profile logs, POPD's recorded interview, and subsequent possession or use of the materials.</p>
    </section>

    <section>
      <h2>Evidence Source and Correlation</h2>
      <p>The images in this packet were identified in recovered phone/message-export data and correlated with matched Google Photos items in Google Takeout data associated with <span class="account-value">keeganhurd@gmail.com</span>. Correlation was based on visual content, screenshot timing, matched filenames or mapped evidence identifiers, phone-image dimensions, Google Photos metadata, and SHA-256 hashes where available. Native device and provider records should be used for final law-enforcement authentication.</p>
    </section>

    <section id="followup">
      <h2>Requested Investigative Follow-Up</h2>
      <ul class="request">
        <li>Confirm that <span class="transmit-value">{RECIPIENT}</span> was associated with Robin Colleen Hurd-Bedner during April 2024.</li>
        <li>Review POPD Case No. PO250004281 and the recorded interview of Robin Hurd-Bedner.</li>
        <li>Obtain or review native iPhone sms.db, attachment records, handle tables, Photos database, and deletion records.</li>
        <li>Determine who possessed and controlled the relevant phone during the April 25, 2024 session.</li>
        <li>Obtain Google account session/device records for <span class="account-value">keeganhurd@gmail.com</span>.</li>
        <li>Obtain Google Photos upload/sync records.</li>
        <li>Obtain Gmail access records concerning the Brianna Tucker notification.</li>
        <li>Obtain Google Business Profile access/audit records for the Florida Crystal location.</li>
        <li>Confirm the message thread and attachment transmissions to <span class="transmit-value">{RECIPIENT}</span>.</li>
        <li>Interview Steve Roberge regarding ownership and nonauthorization.</li>
        <li>Coordinate with POPD concerning the broader 102-item dataset and related statements.</li>
      </ul>
    </section>

    <section id="appendix-a">
      <h2>Appendix A - Florida Crystal Well & Sprinkler Ownership and Account Records</h2>
      <dl class="appendix-meta">
        <div><dt>Google Business Profile location ID</dt><dd><span class="technical-value">7701250605898456430</span></dd></div>
        <div><dt>Business name</dt><dd><span class="entity-value">Florida Crystal Well & Sprinkler</span> as shown in recovered screenshots/OCR and supporting Google Business Profile review data.</dd></div>
        <div><dt>Business address</dt><dd>59 Brittany Lane, Palm Coast, FL 32137</dd></div>
        <div><dt>Manager/admin record</dt><dd>Steve Roberge - MANAGER</dd></div>
        <div><dt>Account-management relationship</dt><dd>The packet states Thomas Keegan Hurd managed the Google Business Profile through the Google account associated with <span class="account-value">keeganhurd@gmail.com</span>; provider records should confirm account/session details.</dd></div>
      </dl>
      <ul>
        <li><code>{esc(str(GBP_DATA))}</code></li>
        <li><code>{esc(str(GBP_ADDITIONAL))}</code></li>
        <li><code>{esc(str(GBP_ADMIN_STEVE))}</code></li>
      </ul>
    </section>

    <section id="appendix-b">
      <h2>Appendix B - Source Files and Forensic Hashes</h2>
      {appendix_b(rows)}
      <h3>Core CSV and HTML Sources</h3>
      <ul>
        <li><code>{esc(str(UNIQUE_CSV))}</code></li>
        <li><code>{esc(str(PHOTOS_CSV))}</code></li>
        <li><code>{esc(str(DEVICE_CSV))}</code></li>
        <li><code>{esc(str(MESSAGES_HTML))}</code></li>
      </ul>
    </section>

    <section id="appendix-c">
      <h2>Appendix C - Full OCR and Technical Audit Trail</h2>
      {appendix_c(rows)}
    </section>

    <section id="appendix-d">
      <h2>Appendix D - Affidavit of Steve Roberge</h2>
      <p><span class="draft">Draft - requires Steve Roberge's review, signature, and notarization</span></p>
      <p>I, Steve Roberge, state that I am the owner of Florida Crystal Well & Sprinkler, a business operating in Palm Coast, Flagler County, Florida. Thomas Keegan Hurd managed the business's Google Business Profile / Google My Business account on my behalf.</p>
      <p>I identify the customer names, lead communications, account pages, and business information depicted in the attached screenshots as Florida Crystal Well & Sprinkler business data.</p>
      <p>I did not authorize Robin Colleen Hurd-Bedner to access, view, download, capture, screenshot, transmit, or otherwise obtain any Florida Crystal Well & Sprinkler business data.</p>
      <p>I did not authorize Thomas Keegan Hurd to disclose the business records to any third party except as necessary to manage the Google Business account on behalf of Florida Crystal Well & Sprinkler.</p>
    </section>

    <p class="muted-note">Generated locally on {esc(now)}. This is a revised standalone draft and does not overwrite the current packet at index.html.</p>
  </main>
</body>
</html>
"""


def write_manifest(rows):
    fieldnames = [
        "EvidenceID",
        "Tier",
        "Exhibit",
        "VisibleContent",
        "ScreenshotCapture",
        "GooglePhotosBackup",
        "BackupDeltaSeconds",
        "TransmissionRecipient",
        "TransmissionTimestamp",
        "CaptureToTransmissionDeltaSeconds",
        "DisplayFilename",
        "FullSHA256",
        "AbbreviatedSHA256",
        "RecipientNumberSource",
        "ImageRelativePath",
        "RevisedImageRelativePath",
        "RevisedImageCopiedFrom",
        "FullSourcePaths",
    ]
    with (OUT_DIR / "included_evidence_manifest.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            ce = row["CanonicalEventId"]
            tier = "Tier 1" if ce in TIER1 else "Tier 2" if ce in TIER2 else "Tier 3"
            writer.writerow({
                "EvidenceID": ce,
                "Tier": tier,
                "Exhibit": row.get("PrimaryExhibitNumber") or row.get("Exhibit"),
                "VisibleContent": row["PacketSubject"],
                "ScreenshotCapture": capture_time(row),
                "GooglePhotosBackup": row.get("GooglePhotosTimeEastern"),
                "BackupDeltaSeconds": backup_delta(row),
                "TransmissionRecipient": RECIPIENT,
                "TransmissionTimestamp": transmission_time(row),
                "CaptureToTransmissionDeltaSeconds": transmission_delta(row),
                "DisplayFilename": main_filename(row),
                "FullSHA256": first(row.get("PrimarySHA256"), row.get("SHA256")),
                "AbbreviatedSHA256": abbreviated_hash(first(row.get("PrimarySHA256"), row.get("SHA256"))),
                "RecipientNumberSource": row.get("RecipientPhoneVisible"),
                "ImageRelativePath": row.get("PacketImageRelPath"),
                "RevisedImageRelativePath": row.get("RevisedImageRelPath"),
                "RevisedImageCopiedFrom": row.get("RevisedImageSourceOriginalRelPath"),
                "FullSourcePaths": "; ".join(source_paths(row)),
            })


def write_hashes(rows):
    lines = ["Florida Crystal Well & Sprinkler evidence SHA-256 manifest", f"Generated: {datetime.now().isoformat(timespec='seconds')}", ""]
    for row in rows:
        lines.append(f"{row['CanonicalEventId']} / {row.get('PrimaryExhibitNumber') or row.get('Exhibit')} | {first(row.get('PrimarySHA256'), row.get('SHA256'))} | {main_filename(row)}")
    (OUT_DIR / "evidence_hashes_sha256.txt").write_text("\n".join(lines), encoding="utf-8")


def write_revision_audit(rows):
    unresolved = []
    if not all("386-347-0544" in (r.get("RecipientPhoneVisible") or "") for r in rows):
        unresolved.append("Not every CE row had recipient-number text in the merged row.")
    if not any("Steve Roberge" in p.read_text(encoding="utf-8", errors="ignore") for p in [GBP_ADMIN_STEVE] if p.exists()):
        unresolved.append("Steve Roberge manager/admin source was not found.")
    unresolved.append("No separately supplied final signed/notarized Steve Roberge affidavit text was found locally; Appendix D is therefore marked draft.")

    lines = [
        "Florida Crystal revised packet audit",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "Headings changed: title/subtitle revised; first-page sections replaced with ownership, strongest chain, conclusion, related investigation, and request.",
        '"Mom" references replaced: user-facing labels now use 386-347-0544; one explanatory source-label note remains near CE-008 as requested.',
        f"Recipient-number source used: {UNIQUE_CSV}; relevant rows state '13863470544 / 1-386-347-0544 visible in export text; not a structured handle.'",
        "Evidence tiering: Tier 1 CE-008, CE-015, CE-007; Tier 2 CE-009, CE-010; Tier 3 CE-005, CE-006.",
        "Timing values verified against merged Unique_Capture_Send_Events.csv and Google_Photos_Phone_Artifact_Corroboration.csv.",
        "Paths moved to appendices: complete source paths and full hashes appear in Appendix B and included_evidence_manifest.csv.",
        "Encoding corrections: malformed narrow-space filename artifacts normalized for display only; original source paths remain preserved in Appendix B/manifest.",
        "",
        "Timing values:",
    ]
    for row in rows:
        lines.append(f"- {row['CanonicalEventId']}: capture={capture_time(row)} backup={row.get('GooglePhotosTimeEastern')} backup_delta={backup_delta(row)} transmission={transmission_time(row) or 'not parsed'} transmission_delta={transmission_delta(row) or 'not parsed'}")
    lines += ["", "Unresolved verification issue:"]
    lines.extend(f"- {item}" for item in unresolved)
    (OUT_DIR / "revision_audit.txt").write_text("\n".join(lines), encoding="utf-8")


def qc(rows):
    html_text = (OUT_DIR / "index_revised.html").read_text(encoding="utf-8")
    mom_count = html_text.count("Mom")
    if mom_count != 1:
        raise RuntimeError(f"Expected exactly one visible Mom source-label note in revised HTML, found {mom_count}")
    for banned in ("Robin committed", "conclusively proves hacking", "must arrest", "theft proven", "criminal liability established"):
        if banned.lower() in html_text.lower():
            raise RuntimeError(f"Banned phrase found: {banned}")
    for ce in CE_IDS:
        if ce not in html_text:
            raise RuntimeError(f"Missing CE item in HTML: {ce}")
    expected = {
        "CE-007": ("0", "21"),
        "CE-008": ("0", "12"),
        "CE-009": ("0", "29"),
        "CE-010": ("0", "20"),
        "CE-015": ("1", "12"),
        "CE-005": ("1", ""),
        "CE-006": ("1", ""),
    }
    by_id = {r["CanonicalEventId"]: r for r in rows}
    for ce, (bdelta, tdelta) in expected.items():
        if backup_delta(by_id[ce]) != bdelta:
            raise RuntimeError(f"{ce} backup delta mismatch")
        if tdelta and transmission_delta(by_id[ce]) != tdelta:
            raise RuntimeError(f"{ce} transmission delta mismatch")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = merge_rows()
    (OUT_DIR / "index_revised.html").write_text(build_html(rows), encoding="utf-8")
    write_manifest(rows)
    write_hashes(rows)
    write_revision_audit(rows)
    qc(rows)
    print(f"Wrote {OUT_DIR / 'index_revised.html'}")
    print(f"Wrote {OUT_DIR / 'included_evidence_manifest.csv'}")
    print(f"Wrote {OUT_DIR / 'evidence_hashes_sha256.txt'}")
    print(f"Wrote {OUT_DIR / 'revision_audit.txt'}")
    print("QC passed")


if __name__ == "__main__":
    main()
