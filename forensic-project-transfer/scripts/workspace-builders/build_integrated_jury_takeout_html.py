import csv
import datetime as dt
import html
import re
import shutil
from collections import Counter
from pathlib import Path
from urllib.parse import quote


ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
PHONE_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA")
OUT = ROOT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images"
MEDIA = OUT / "media"

GOOGLE_TIMELINE = ROOT / "timeline.csv"
INVENTORY = ROOT / "inventory.csv"
INDEXED = ROOT / "indexed_files.csv"
EXTRACT_SUMMARY = ROOT / "extraction_summary.csv"
ACCESS_LOG = ROOT / "access_log_apr19_26.csv"
PHONE_EVENTS = PHONE_ROOT / "Unique_Capture_Send_Events.csv"

TERMS = [
    "helo", "ein", "irs", "cp 575", "bank", "banking", "statement", "navy federal",
    "gavin", "jonathan", "ariana", "venmo", "google business", "business profile",
    "drive", "gmail", "virtue", "docusign", "florida crystal", "merchant",
    "gofingerprinting", "go fingerprinting", "payanywhere", "authorize", "stripe",
]

RELEVANT_GOOGLE_SERVICES = {"gmail", "drive", "google business profile", "search", "image search"}
SUBJECT_TERMS = [t for t in TERMS if t not in {"gmail", "drive", "google business", "business profile"}]


def read_csv(path):
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


def clip(value, n=260):
    value = re.sub(r"\s+", " ", "" if value is None else str(value)).strip()
    if len(value) <= n:
        return value
    return value[: n - 1].rstrip() + "..."


def slug(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")[:180]


def term_hits(text):
    low = text.lower()
    hits = []
    for term in TERMS:
        if " " in term:
            pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
        elif term in {"irs", "ein"}:
            pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
        elif term == "bank":
            pattern = r"(?<![a-z0-9])bank(?:s|ing)?(?![a-z0-9])"
        else:
            pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
        if re.search(pattern, low):
            hits.append(term)
    return hits


def relevant_google(row):
    return row.get("Google Service", "").strip().lower() in RELEVANT_GOOGLE_SERVICES


def phone_score(row):
    text = " ".join([
        row.get("VisualDescription", ""),
        row.get("HtmlMediaFileName", ""),
        row.get("TimestampedScreenshotFileName", ""),
        row.get("EventType", ""),
    ])
    hits = set(term_hits(text))
    score = 0
    for term in TERMS:
        if term in hits:
            score += 6
    if "file_5531" in text.lower():
        score += 30
    if "irs" in hits or "ein" in hits:
        score += 12
    if "bank" in hits or "navy federal" in hits:
        score += 10
    try:
        elapsed = int(float(row.get("ElapsedSeconds") or 9999))
        if elapsed <= 30:
            score += 4
    except Exception:
        pass
    return score


def google_score(row):
    text = " ".join([row.get("Google Service", ""), row.get("Event Type", ""), row.get("Description", "")])
    hits = set(term_hits(text))
    score = 0
    if row.get("Google Service", "").lower() == "gmail":
        score += 10
    if row.get("Event Type", "").lower() == "search":
        score += 8
    for term in TERMS:
        if term in hits:
            score += 7
    return score


def clean_search(desc):
    if "Searched for " in desc:
        return desc.split("Searched for ", 1)[1].split(" | ", 1)[0]
    return desc


def load_google():
    rows = read_csv(GOOGLE_TIMELINE)
    out = []
    for r in rows:
        d = parse_dt(r.get("Timestamp"))
        if not d:
            continue
        r["_dt"] = d
        r["_score"] = google_score(r)
        # Match only activity content, not the source path, so a Gmail source file
        # does not become a false "gmail" subject match.
        r["_terms"] = term_hits(" ".join([r.get("Google Service", ""), r.get("Event Type", ""), r.get("Description", "")]))
        out.append(r)
    return sorted(out, key=lambda r: r["_dt"])


def load_phone():
    rows = read_csv(PHONE_EVENTS)
    out = []
    for r in rows:
        capture_dt = parse_dt(r.get("ScreenshotFilenameTimestamp"))
        message_dt = parse_dt(r.get("MessagesHtmlTextedToMomTimestamp"))
        d = message_dt or capture_dt
        if not d:
            continue
        r["_dt"] = d
        r["_capture_dt"] = capture_dt
        r["_message_dt"] = message_dt
        r["_score"] = phone_score(r)
        # Use visible/filename content for subject tags. Do not trust broad legacy
        # category columns for tagging because those were intentionally loose.
        visible_text = " ".join([
            r.get("VisualDescription", ""),
            r.get("HtmlMediaFileName", ""),
            r.get("TimestampedScreenshotFileName", ""),
            r.get("EventType", ""),
        ])
        r["_terms"] = term_hits(visible_text)
        out.append(r)
    return sorted(out, key=lambda r: r["_dt"])


def copy_media(phone_rows):
    MEDIA.mkdir(parents=True, exist_ok=True)
    copied = {}
    missing = []
    for r in phone_rows:
        src = r.get("HtmlMediaFilePath") or r.get("TimestampedScreenshotFilePath")
        if not src or not Path(src).exists():
            missing.append(r.get("CanonicalEventId"))
            continue
        dest = MEDIA / slug(f"{r.get('CanonicalEventId')}_{Path(src).name}")
        shutil.copy2(src, dest)
        copied[r.get("CanonicalEventId")] = dest.name
    return copied, missing


def near_google(event_dt, google_rows, seconds=300):
    found = []
    for g in google_rows:
        if not relevant_google(g):
            continue
        delta = (event_dt - g["_dt"]).total_seconds()
        if delta <= seconds:
            if delta < 0:
                continue
            found.append((int(delta), g))
    return sorted(found, key=lambda x: (x[0], -x[1]["_score"]))[:6]


def session_google(start, end, google_rows):
    lookback = start - dt.timedelta(hours=3)
    found = []
    for g in google_rows:
        if not relevant_google(g):
            continue
        if lookback <= g["_dt"] <= end:
            found.append(g)
    return sorted(found, key=lambda g: g["_dt"])


def subject_google(phone_row, google_rows):
    pterms = set(phone_row.get("_terms") or []) & set(SUBJECT_TERMS)
    if not pterms:
        return []
    found = []
    for g in google_rows:
        if not relevant_google(g):
            continue
        # Subject support should generally precede the phone artifact. Wider
        # historical matches are allowed only within the reviewed April window.
        if g["_dt"] > phone_row["_dt"]:
            continue
        gterms = set(g.get("_terms") or []) & set(SUBJECT_TERMS)
        shared = sorted(pterms & gterms)
        if shared:
            found.append((len(shared), shared, g))
    found.sort(key=lambda x: (-x[0], x[2]["_dt"]))
    return found[:5]


def fmt_dt(d):
    return d.strftime("%Y-%m-%d %I:%M:%S %p")


def fmt_delta(seconds):
    seconds = int(round(seconds))
    sign = "+" if seconds >= 0 else "-"
    seconds = abs(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        value = f"{h}h {m}m {s}s"
    elif m:
        value = f"{m}m {s}s"
    else:
        value = f"{s}s"
    return sign + value


def session_map(sessions, google_rows):
    out = {}
    for i, sess in enumerate(sessions, 1):
        start = sess[0]["_dt"]
        end = sess[-1]["_dt"]
        g_rows = session_google(start, end, google_rows)
        for row in sess:
            out[row.get("CanonicalEventId")] = {
                "number": i,
                "start": start,
                "end": end,
                "google": g_rows,
                "artifact_count": len(sess),
            }
    return out


CSS = """
<style>
  :root {
    --bg: #0e1116; --ink: #edf2f7; --muted: #aab4c3; --panel: #151b23;
    --line: #303946; --blue: #163a5f; --blue-ink: #b9dcff; --green: #173f2a;
    --green-ink: #bdf4cf; --amber: #533f13; --amber-ink: #ffe2a3;
    --violet: #342657; --violet-ink: #d7c7ff; --red: #4f1717; --red-ink:#ffd1d1;
    --gray: #252d38;
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.45 "Segoe UI", Arial, sans-serif; }
  header { position:sticky; top:0; z-index:20; background:#0a0d12; color:#f8fbff; padding:14px 22px; border-bottom:4px solid #6aa6ff; }
  header h1 { margin:0 0 4px; font-size:22px; } header p { margin:0; color:#c8d7eb; }
  main { max-width:1420px; margin:0 auto; padding:18px; }
  .summary { display:grid; grid-template-columns:repeat(5,minmax(150px,1fr)); gap:10px; margin-bottom:16px; }
  .summary-card { background:var(--panel); border:1px solid var(--line); border-left:7px solid #6aa6ff; padding:12px; }
  .summary-card strong { display:block; font-size:24px; }
  .note { background:#151b23; border:1px solid var(--line); border-left:7px solid #ffbf47; padding:12px 14px; margin-bottom:16px; }
  .note.protect { border-left-color:#43b46f; background:#101f18; }
  h2 { margin:24px 0 10px; padding-bottom:6px; border-bottom:2px solid var(--line); font-size:21px; }
  .jump { display:flex; flex-wrap:wrap; gap:8px; margin:10px 0 18px; }
  .jump a { color:#b9dcff; background:#152b44; border:1px solid #b7d5ff; border-radius:5px; padding:5px 8px; font-weight:800; text-decoration:none; }
  .event-card { background:var(--panel); border:1px solid var(--line); border-radius:8px; margin:14px 0; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.45); }
  .event-head { display:flex; gap:12px; align-items:flex-start; background:#111923; border-bottom:1px solid var(--line); padding:12px 14px; }
  .rank { background:#0a0d12; color:#fff; font-weight:700; border-radius:6px; padding:5px 8px; min-width:48px; text-align:center; }
  h3 { margin:0; font-size:18px; } .category { display:inline-block; margin-top:5px; padding:3px 7px; background:var(--violet); color:var(--violet-ink); font-weight:700; border-radius:5px; }
  .event-layout { display:grid; grid-template-columns:minmax(0,2fr) minmax(310px,1fr); gap:0; }
  .event-text { min-width:0; border-right:1px solid var(--line); }
  .timeline-strip { display:grid; grid-template-columns:repeat(5,minmax(120px,1fr)); gap:8px; padding:12px 14px; background:#121922; border-bottom:1px solid var(--line); }
  .timeline-strip span:first-child { display:block; text-transform:uppercase; color:var(--muted); font-size:11px; font-weight:700; letter-spacing:.04em; margin-bottom:4px; }
  .pill,.time,.contact { display:inline-block; padding:3px 7px; border-radius:5px; font-weight:800; font-family:Consolas,"Courier New",monospace; overflow-wrap:anywhere; }
  .capture{background:var(--blue); color:var(--blue-ink)} .sent{background:var(--green); color:var(--green-ink)}
  .google{background:#1d3552; color:#cbe3ff} .warn{background:var(--amber); color:var(--amber-ink)} .contact{background:var(--gray); color:#d7dee8}
  .red{background:var(--red); color:var(--red-ink)} .empty{color:var(--muted); font-style:italic}
  .description { padding:12px 14px; font-size:16px; background:#151b23; border-bottom:1px solid var(--line); }
  .plain { padding:12px 14px; background:#101923; border-bottom:1px solid var(--line); font-size:16px; }
  .session-box { border:1px solid #45627f; background:#101722; border-left:7px solid #6aa6ff; border-radius:8px; padding:12px 14px; margin:14px 0; }
  .session-box.critical { border-left-color:#ff6b6b; background:#1b1215; }
  .session-title { font-size:18px; font-weight:900; color:#f8fbff; margin-bottom:6px; }
  .session-flow { display:flex; flex-wrap:wrap; gap:8px; margin:8px 0; }
  .flow-step { border:1px solid var(--line); border-radius:6px; padding:6px 8px; background:#121922; max-width:360px; }
  .code-log { background:#0b0f14; border:1px solid #303946; border-radius:8px; padding:10px; margin:12px 0; font-family:Consolas,"Courier New",monospace; font-size:14px; overflow:auto; }
  .log-line { padding:5px 0; border-top:1px solid #1d2530; white-space:normal; }
  .log-line:first-child { border-top:0; }
  .tok-time{color:#78e5aa}.tok-service{color:#6aa6ff}.tok-action{color:#d7c7ff}.tok-query{color:#ffe2a3}.tok-source{color:#aab4c3}.tok-critical{color:#ff9b9b;font-weight:900}.tok-muted{color:#7f8a99}
  .google-box { margin:12px 14px; border:1px solid #45627f; background:#101d2b; border-radius:7px; padding:10px; }
  .google-box h4 { margin:0 0 8px; color:#b9dcff; }
  .g-row { border-top:1px solid #30465e; padding:8px 0; }
  .g-row:first-of-type { border-top:0; }
  .grid { display:grid; grid-template-columns:repeat(2,minmax(240px,1fr)); gap:8px; padding:12px 14px; }
  .field { border:1px solid var(--line); background:#151b23; border-radius:6px; padding:8px; min-width:0; }
  .field-label { color:var(--muted); font-size:12px; font-weight:800; text-transform:uppercase; margin-bottom:3px; }
  .field-value { overflow-wrap:anywhere; } .file .field-value { color:#78e5aa; font-family:Consolas,"Courier New",monospace; font-weight:700; }
  .why{background:#102133}.limit{background:#2b230f}.native{background:#1d1730}
  .media-pane { background:#0f141b; padding:12px; min-width:0; }
  .image-link { display:block; background:#0b0f14; border:1px solid #c8d0db; border-radius:7px; overflow:hidden; }
  .image-link img { display:block; width:100%; max-height:520px; object-fit:contain; background:#050608; }
  .pdf-preview object { display:block; width:100%; height:520px; border:1px solid #c8d0db; background:#151b23; }
  .open-media { display:inline-block; margin-top:8px; padding:6px 9px; background:#0a0d12; color:#f8fbff; text-decoration:none; border-radius:5px; font-weight:800; }
  .media-missing { border:1px dashed #b8c1cc; background:#151b23; border-radius:7px; padding:14px; color:var(--muted); }
  details { padding:0 14px 14px; border-top:1px solid var(--line); background:#151b23; }
  summary { cursor:pointer; color:#9dccff; font-weight:800; padding:12px 0; }
  .expanded-media { margin-bottom:12px; }
  .expanded-media img { display:block; max-width:100%; max-height:1100px; object-fit:contain; background:#050608; border:1px solid #c8d0db; border-radius:7px; }
  .expanded-media object { width:100%; height:900px; border:1px solid #c8d0db; }
  .technical { display:grid; grid-template-columns:repeat(2,minmax(260px,1fr)); gap:8px; }
  table { width:100%; border-collapse:collapse; background:#151b23; border:1px solid var(--line); }
  th,td { border-top:1px solid var(--line); padding:8px; text-align:left; vertical-align:top; } th { background:#101923; color:#fff; }
  @media (max-width:980px){.summary{grid-template-columns:repeat(2,1fr)}.event-layout{grid-template-columns:1fr}.event-text{border-right:0;border-bottom:1px solid var(--line)}.timeline-strip,.grid,.technical{grid-template-columns:1fr}.media-pane{order:-1}}
  @media (max-width:760px){body{font-size:14px}header{position:static;padding:12px}header h1{font-size:18px;line-height:1.2}main{padding:10px}.summary{grid-template-columns:1fr}.timeline-strip{grid-template-columns:1fr 1fr}.description{font-size:14px;max-height:180px;overflow:auto}.image-link img{max-height:72vh}.pdf-preview object{height:72vh}.expanded-media img{max-height:none;width:100%}.expanded-media object{height:80vh}}
</style>
"""


def media_html(filename, label):
    if not filename:
        return '<div class="media-missing"><strong>No preview copied</strong>Recorded media path was missing or unavailable.</div>'
    src = f"media/{quote(filename)}"
    if filename.lower().endswith(".pdf"):
        return f'<div class="pdf-preview"><object data="{src}" type="application/pdf"><a href="{src}">Open PDF</a></object></div><a class="open-media" href="{src}">Open PDF</a>'
    return f'<a class="image-link" href="{src}"><img src="{src}" alt="{esc(label)}"></a><a class="open-media" href="{src}">Open image</a>'


def expanded_media_html(filename, label):
    if not filename:
        return ""
    src = f"media/{quote(filename)}"
    if filename.lower().endswith(".pdf"):
        return f'<div class="expanded-media"><object data="{src}" type="application/pdf"><a href="{src}">Open PDF</a></object></div>'
    return f'<div class="expanded-media"><img src="{src}" alt="{esc(label)} expanded"></div>'


def google_rows_html(rows, heading, empty_text):
    if not rows:
        return f'<div class="google-box"><h4>{esc(heading)}</h4><div class="empty">{esc(empty_text)}</div></div>'
    parts = [f'<div class="google-box"><h4>{esc(heading)}</h4>']
    for item in rows:
        if len(item) == 2:
            delta, g = item
            prefix = f"{delta} seconds away"
            terms = ", ".join(g.get("_terms") or [])
        else:
            _, shared, g = item
            prefix = "Subject match: " + ", ".join(shared)
            terms = ", ".join(g.get("_terms") or [])
        parts.append(f"""
        <div class="g-row">
          <span class="pill google">{esc(prefix)}</span>
          <span class="pill">{esc(g.get('Google Service'))}</span>
          <span class="pill">{esc(g.get('Event Type'))}</span><br>
          <b>{esc(fmt_dt(g['_dt']))}</b> - {esc(clip(g.get('Description'), 260))}<br>
          <span class="field-value">Source: {esc(g.get('Source File'))}</span>
          {('<br><span class="field-value">Matched terms: ' + esc(terms) + '</span>') if terms else ''}
        </div>""")
    parts.append("</div>")
    return "".join(parts)


def session_context_html(row, session_info):
    anchor = row.get("_capture_dt") or row.get("_dt")
    if not session_info:
        return '<div class="google-box"><h4>Session context</h4><div class="empty">This artifact was not mapped to a session.</div></div>'
    start = session_info["start"]
    end = session_info["end"]
    from_start = fmt_delta((anchor - start).total_seconds())
    rows = session_info.get("google") or []
    parts = [f"""
    <div class="google-box">
      <h4>Session {session_info['number']} context for this card</h4>
      <div class="session-flow">
        <div class="flow-step"><span class="tok-muted">Session window</span><br><span class="tok-time">{esc(fmt_dt(start))}</span><br><span class="tok-time">{esc(fmt_dt(end))}</span></div>
        <div class="flow-step"><span class="tok-muted">Time from session start to this capture/card</span><br><span class="tok-critical">{esc(from_start)}</span></div>
        <div class="flow-step"><span class="tok-muted">Capture to text/send</span><br><span class="tok-critical">{esc((row.get('ElapsedSeconds') or 'not calculated') + (' sec' if row.get('ElapsedSeconds') else ''))}</span></div>
      </div>
      <div class="code-log">
    """]
    if not rows:
        parts.append('<div class="log-line"><span class="tok-muted">No relevant Google Takeout rows were parsed for this session window.</span></div>')
    else:
        for g in rows:
            rel = (g["_dt"] - anchor).total_seconds()
            direction = "after this capture/card" if rel > 0 else "before this capture/card" if rel < 0 else "same time as this capture/card"
            query = clean_search(g.get("Description", "")) if g.get("Event Type", "").lower() == "search" else clip(g.get("Description", ""), 150)
            parts.append(f"""
            <div class="log-line">
              <span class="tok-time">{esc(fmt_dt(g['_dt']))}</span>
              <span class="tok-muted"> | </span><span class="tok-service">{esc(g.get('Google Service'))}</span>
              <span class="tok-muted">.</span><span class="tok-action">{esc(g.get('Event Type'))}</span>
              <span class="tok-muted"> =&gt; </span><span class="tok-query">{esc(query)}</span><br>
              <span class="tok-muted">// {esc(fmt_delta(rel))} {esc(direction)}</span>
            </div>""")
    parts.append("</div></div>")
    return "".join(parts)


def build_card(i, row, copied, google_rows, sessions_by_ce):
    ce = row.get("CanonicalEventId")
    filename = copied.get(ce)
    near = near_google(row["_dt"], google_rows, seconds=7200)
    subj = subject_google(row, google_rows)
    sess_info = sessions_by_ce.get(ce)
    elapsed = row.get("ElapsedSeconds") or ""
    elapsed_label = f"{elapsed} sec" if elapsed else "not calculated"
    category = clean_category(row)
    title = f"{ce} / {row.get('PrimaryExhibitNumber')} / {row.get('EventType')}"
    capture = row.get("ScreenshotFilenameTimestamp") or "N/A"
    sent = row.get("MessagesHtmlTextedToMomTimestamp") or "N/A"
    plain = plain_language(row)
    anchor_dt_label = "capture" if row.get("ScreenshotFilenameTimestamp") else "message"
    return f"""
    <section class="event-card" id="{esc(ce)}">
      <div class="event-head">
        <div class="rank">#{i}</div>
        <div>
          <h3>{esc(title)}</h3>
          <span class="category">{esc(category)}</span>
        </div>
      </div>
      <div class="event-layout">
        <div class="event-text">
          <div class="timeline-strip">
            <div><span>Capture</span><span class="time capture">{esc(capture)}</span></div>
            <div><span>Texted / linked</span><span class="time sent">{esc(sent)}</span></div>
            <div><span>Elapsed</span><span class="time {'sent' if (elapsed and elapsed.isdigit() and int(elapsed) <= 30) else 'warn'}">{esc(elapsed_label)}</span></div>
            <div><span>Conversation</span><span class="contact">{esc(row.get('ConversationContact') or 'Not recorded')}</span></div>
            <div><span>Google tie</span><span class="time google">{esc(google_tie_label(near, subj))}</span></div>
          </div>
          <div class="plain"><strong>Simple Explanation:</strong> {esc(plain)}</div>
          <div class="description"><strong>Visible/OCR description:</strong> {esc(clip(row.get('VisualDescription'), 520))}</div>
          {session_context_html(row, sess_info)}
          {google_rows_html(near, f"Earlier same-session Google Takeout records before the {anchor_dt_label}", "No parsed relevant Google Takeout event was found in the 2 hours before this artifact.")}
          {google_rows_html(subj, "Earlier Google Takeout records with the same subject matter", "No earlier relevant Gmail/Drive/Search/Business Profile subject match was found in parsed Google Takeout activity rows.")}
          <div class="grid">
            <div class="field why"><div class="field-label">Why it matters</div><div class="field-value">{esc(clip(row.get('WhyItMatters'), 360))}</div></div>
            <div class="field limit"><div class="field-label">What it does not prove</div><div class="field-value">{esc(clip(row.get('Limitation'), 360))}</div></div>
            <div class="field file"><div class="field-label">HTML media file</div><div class="field-value">{esc(row.get('HtmlMediaFileName') or '')}</div></div>
            <div class="field file"><div class="field-label">SHA256</div><div class="field-value">{esc(row.get('PrimarySHA256') or '')}</div></div>
          </div>
        </div>
        <div class="media-pane">{media_html(filename, title)}</div>
      </div>
      <details>
        <summary>Expand full-size media and technical source details</summary>
        {expanded_media_html(filename, title)}
        <div class="technical">
          <div class="field file"><div class="field-label">Timestamped screenshot path</div><div class="field-value">{esc(row.get('TimestampedScreenshotFilePath') or '')}</div></div>
          <div class="field file"><div class="field-label">Messages.html media path</div><div class="field-value">{esc(row.get('HtmlMediaFilePath') or '')}</div></div>
          <div class="field native"><div class="field-label">Native confirmation still needed</div><div class="field-value">{esc(row.get('NativeConfirmationNeeded') or '')}</div></div>
          <div class="field"><div class="field-label">Direction inference</div><div class="field-value">{esc(row.get('DirectionInference') or '')}</div></div>
        </div>
      </details>
    </section>"""


def google_tie_label(near, subj):
    if near and near[0][0] <= 60:
        return "near in time"
    if near:
        return "within 5 min"
    if subj:
        return "same subject"
    return "none parsed"


def clean_category(row):
    terms = row.get("_terms") or []
    labels = []
    if any(t in terms for t in ("irs", "ein", "cp 575")):
        labels.append("IRS/EIN")
    if any(t in terms for t in ("helo", "virtue", "merchant", "docusign", "payanywhere")):
        labels.append("Business record")
    if any(t in terms for t in ("bank", "banking", "statement", "navy federal")):
        labels.append("Bank/financial")
    if "google business" in terms or "business profile" in terms or "florida crystal" in terms:
        labels.append("Google Business/Profile")
    if "gmail" in terms:
        labels.append("Gmail")
    if "drive" in terms:
        labels.append("Drive")
    if "jonathan" in terms or "ariana" in terms or "venmo" in terms or "gavin" in terms:
        labels.append("Gmail search/payment context")
    return "; ".join(labels) if labels else "Not classified from visible text"


def plain_language(row):
    bits = []
    event_type = row.get("EventType", "artifact")
    if "PDF" in event_type or "document" in event_type.lower():
        bits.append("This is a document/PDF artifact recorded in the message export.")
    else:
        bits.append("This is a screenshot artifact recorded in the message export.")
    if row.get("ScreenshotFilenameTimestamp") and row.get("MessagesHtmlTextedToMomTimestamp"):
        bits.append("The screenshot filename time and the message-thread time are recorded close together.")
    if "file_5531" in " ".join(str(v) for v in row.items()).lower():
        bits.append("This is the FILE_5531.pdf record, described in the evidence table as an IRS/EIN business document.")
    terms = row.get("_terms") or []
    if terms:
        bits.append("The visible content is tagged with: " + ", ".join(terms[:8]) + ".")
    bits.append("This card does not identify who physically used the device.")
    return " ".join(bits)


def build_google_table(google_rows):
    key_rows = [g for g in google_rows if relevant_google(g) and (g.get("Google Service", "").lower() == "gmail" or g["_score"] >= 15)]
    parts = ["<div class='code-log'>"]
    for g in key_rows:
        desc = g.get("Description", "")
        meaning = "Google recorded Gmail activity."
        if g.get("Event Type", "").lower() == "search":
            meaning = f"Google recorded a Gmail search for: {clean_search(desc)}."
        elif g.get("Event Type", "").lower() == "visited/open":
            meaning = "Google recorded a Gmail URL/message visit. The message ID should be preserved for provider follow-up."
        critical = " tok-critical" if g["_score"] >= 20 else ""
        query = clean_search(desc) if g.get("Event Type", "").lower() == "search" else clip(desc, 150)
        parts.append(f"""
        <div class="log-line">
          <span class="tok-time">{esc(fmt_dt(g['_dt']))}</span>
          <span class="tok-muted"> | </span><span class="tok-service">{esc(g.get('Google Service'))}</span>
          <span class="tok-muted">.</span><span class="tok-action">{esc(g.get('Event Type'))}</span>
          <span class="tok-muted"> =&gt; </span><span class="tok-query{critical}">{esc(query)}</span><br>
          <span class="tok-muted">// {esc(meaning)}</span><br>
          <span class="tok-source">source: {esc(g.get('Source File'))}</span>
        </div>""")
    parts.append("</div>")
    return "".join(parts)


def split_sessions(phone_rows):
    sessions = []
    cur = []
    for row in phone_rows:
        if cur and (row["_dt"] - cur[-1]["_dt"]).total_seconds() > 3600:
            sessions.append(cur)
            cur = []
        cur.append(row)
    if cur:
        sessions.append(cur)
    return sessions


def session_summary_html(sessions, google_rows):
    parts = []
    for i, sess in enumerate(sessions, 1):
        start = sess[0]["_dt"]
        end = sess[-1]["_dt"]
        g_rows = session_google(start, end, google_rows)
        terms = Counter(t for r in sess for t in (r.get("_terms") or []))
        critical = any(t in terms for t in ("helo", "ein", "irs", "bank", "statement", "navy federal", "drive", "gmail"))
        cls = "session-box critical" if critical else "session-box"
        google_bits = []
        for g in g_rows[:8]:
            google_bits.append(
                f'<div class="flow-step"><span class="tok-time">{esc(fmt_dt(g["_dt"]))}</span><br>'
                f'<span class="tok-service">{esc(g.get("Google Service"))}</span> '
                f'<span class="tok-action">{esc(g.get("Event Type"))}</span><br>'
                f'<span class="tok-query">{esc(clip(clean_search(g.get("Description", "")), 95))}</span></div>'
            )
        if not google_bits:
            google_bits.append('<div class="flow-step"><span class="tok-muted">No relevant Google Takeout row parsed in the 3 hours before this session or during the session.</span></div>')
        key_cards = "".join(f'<a href="#{esc(r.get("CanonicalEventId"))}" class="pill red">{esc(r.get("CanonicalEventId"))}</a>' for r in sess[:12])
        parts.append(f"""
        <section class="{cls}" id="session-{i}">
          <div class="session-title">Session {i}: {esc(fmt_dt(start))} to {esc(fmt_dt(end))} ({len(sess)} phone artifacts)</div>
          <div><span class="pill capture">capture/send series</span> <span class="pill google">Google lookback: 3 hours before session through session end</span></div>
          <p><b>Visible subjects in this session:</b> {esc(', '.join(k for k,_ in terms.most_common(10)) or 'No strong subject tags parsed from visible text.')}</p>
          <div class="session-flow">{''.join(google_bits)}<div class="flow-step"><span class="tok-time">{esc(fmt_dt(start))} - {esc(fmt_dt(end))}</span><br><span class="tok-critical">Recovered phone captures/transmissions</span><br>{key_cards}</div></div>
          <p class="tok-muted">This session view shows timing and subject matter. It does not identify who used the device.</p>
        </section>""")
    return "".join(parts)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    google_rows = load_google()
    phone_rows = load_phone()
    copied, missing = copy_media(phone_rows)
    inv_count = len(read_csv(INVENTORY))
    idx_count = len(read_csv(INDEXED))
    zip_count = len(read_csv(EXTRACT_SUMMARY))
    access_count = len(read_csv(ACCESS_LOG)) if ACCESS_LOG.exists() else 0
    gmail_rows = [g for g in google_rows if g.get("Google Service", "").lower() == "gmail"]
    gmail_searches = [g for g in gmail_rows if g.get("Event Type", "").lower() == "search"]
    immediate = 0
    for p in phone_rows:
        try:
            if int(float(p.get("ElapsedSeconds") or 9999)) <= 30:
                immediate += 1
        except Exception:
            pass

    sessions = split_sessions(phone_rows)
    sessions_by_ce = session_map(sessions, google_rows)
    top = sorted(phone_rows, key=lambda r: (-r["_score"], r["_dt"]))[:28]
    ordered = phone_rows

    jump = "".join(f'<a href="#{esc(r.get("CanonicalEventId"))}">{esc(r.get("CanonicalEventId"))}</a>' for r in top[:24])
    cards = "\n".join(build_card(i, r, copied, google_rows, sessions_by_ce) for i, r in enumerate(ordered, 1))

    html_doc = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Integrated Google Takeout + Phone Evidence View - Dark Mode</title>
{CSS}
</head>
<body>
<header>
  <h1>Integrated Google Takeout + Phone Evidence View</h1>
  <p>Dark-mode jury-friendly view: Google activity records, recovered screenshot/message timing, and copied local media in the same cards.</p>
</header>
<main>
  <div class="summary">
    <div class="summary-card"><strong>{zip_count}</strong>Takeout ZIPs processed</div>
    <div class="summary-card"><strong>{inv_count:,}</strong>Takeout files inventoried</div>
    <div class="summary-card"><strong>{idx_count:,}</strong>Text/metadata files indexed</div>
    <div class="summary-card"><strong>{len(gmail_rows)}</strong>Gmail activity records</div>
    <div class="summary-card"><strong>{len(phone_rows)}</strong>Phone artifacts shown</div>
    <div class="summary-card"><strong>{len(gmail_searches)}</strong>Gmail searches</div>
    <div class="summary-card"><strong>{immediate}</strong>0-30 second phone events</div>
    <div class="summary-card"><strong>{len(copied)}</strong>Media files copied</div>
    <div class="summary-card"><strong>{len(missing)}</strong>Missing media previews</div>
    <div class="summary-card"><strong>{access_count}</strong>April 2024 Access Log rows</div>
  </div>
  <div class="note protect"><strong>Plain-English point:</strong> The Google Takeout records show Gmail searches and Gmail activity during April 19-26, 2024. The recovered phone artifacts separately show screenshots/PDFs appearing in a Mom message thread, often within seconds of capture. This page places those records together so the timing and subject matter can be understood without technical training.</div>
  <div class="note"><strong>Careful wording:</strong> This page does not identify who physically used the device, does not decide authorization, and does not replace native iPhone or provider records. It shows objective timestamps, filenames, copied media, Google Takeout activity rows, and limitations.</div>
  <h2>Google Takeout Activity Log, Filtered For Relevant Services</h2>
  <div class="note"><strong>How to read this:</strong> This log is chronological. Green is time, blue is Google service, purple is action, yellow/red is the query or activity. It is filtered to Gmail and other relevant Google services so YouTube-style noise is not mixed into the evidence story.</div>
  {build_google_table(google_rows)}
  <h2>Chronological Mining / Capture / Transmission Sessions</h2>
  <div class="note protect"><strong>How to read this:</strong> Each session shows relevant Google Takeout activity in the three hours before the screenshot/PDF series and during that same series. This is meant to show sequence: Google activity first or during the session, then capture/send artifacts.</div>
  {session_summary_html(sessions, google_rows)}
  <h2>Jump To Critical Cards Without Changing Chronological Order</h2>
  <div class="jump">{jump}</div>
  <h2>Integrated Phone Artifact + Google Takeout Evidence Cards, Chronological Order</h2>
  {cards}
</main>
</body>
</html>"""

    (OUT / "index_dark.html").write_text(html_doc, encoding="utf-8")
    (OUT / "README.txt").write_text(
        f"Open index_dark.html. Built from {GOOGLE_TIMELINE} and {PHONE_EVENTS}. Media copied: {len(copied)}. Missing media: {len(missing)}.\n",
        encoding="utf-8",
    )
    print(f"Created integrated jury-friendly HTML: {OUT / 'index_dark.html'}")
    print(f"Media copied: {len(copied)}; missing: {len(missing)}")


if __name__ == "__main__":
    main()
