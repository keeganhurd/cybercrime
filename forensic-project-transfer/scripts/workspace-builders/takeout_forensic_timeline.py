import csv
import datetime as dt
import email
import email.policy
import html
import json
import os
import re
import sqlite3
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
EXTRACT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
OUT_DIR = EXTRACT_DIR / "_forensic_outputs"

START = dt.datetime(2024, 4, 19, 0, 0, 0)
END = dt.datetime(2024, 4, 26, 23, 59, 59)

TEXT_EXTS = {
    ".json", ".html", ".htm", ".csv", ".txt", ".xml", ".mbox", ".log",
    ".sqlite", ".sqlite3", ".db", ".sql", ".tsv", ".ics"
}

MEDIA_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".heic", ".webp", ".mp4", ".mov",
    ".avi", ".mkv", ".mp3", ".wav", ".m4a", ".pdf", ".zip", ".gz", ".tgz"
}

KEYWORDS = [
    "Jonathan", "Braese", "Breas", "Jonathan Brease",
    "keeganhurd@gmail.com",
    "GoFingerprinting", "Go Fingerprinting",
    "Helo", "Merchant", "Authorize.net", "Stripe",
    "Bank", "Banking", "Statement", "Checking", "Savings",
    "Tax", "EIN", "Password", "Drive", "Gmail", "Inbox",
    "Business", "Google Business", "Google My Business",
    "Mom", "Robin", "Elijah",
]

SERVICES = [
    ("Gmail", ["mail", "gmail", "inbox", "message"]),
    ("Google Drive", ["drive", "docs", "sheets", "slides", "download", "upload", "shared"]),
    ("Google Account", ["account", "security", "login", "session", "device", "password", "recovery"]),
    ("Google Photos", ["photos", "google photos"]),
    ("Google Business Profile", ["business profile", "google my business", "my business"]),
    ("Chrome Sync", ["chrome", "browser", "sync"]),
    ("Google Search", ["search", "searched"]),
    ("Device Activity", ["device", "iphone", "ios", "android", "windows", "mac"]),
]

DATE_PATTERNS = [
    re.compile(r"2024[-/](?:04|4)[-/](?:19|20|21|22|23|24|25|26)(?:[ T][0-9:.+-Z]*)?", re.I),
    re.compile(r"(?:Apr|April)\s+(?:19|20|21|22|23|24|25|26),?\s+2024(?:[, ]+[0-9: ]+(?:AM|PM)?)?", re.I),
    re.compile(r"(?:19|20|21|22|23|24|25|26)\s+(?:Apr|April)\s+2024(?:[, ]+[0-9: ]+(?:AM|PM)?)?", re.I),
]

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DEVICE_RE = re.compile(r"\b(iPhone|iOS|Android|Windows|Mac(?:intosh)?|Chrome|Safari|Firefox|Edge|Pixel|iPad)\b", re.I)
EMAIL_SUBJECT_RE = re.compile(r"^Subject:\s*(.+)$", re.I)
QUERY_RE = re.compile(r"\b(?:Searched for|Search query|query)\s*:?\s*[\"']?([^\"'<\n\r]{1,160})", re.I)


def safe_extract(zip_path: Path, dest: Path):
    errors = []
    extracted = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            target = dest / info.filename
            try:
                resolved = target.resolve()
                if not str(resolved).lower().startswith(str(dest.resolve()).lower()):
                    raise ValueError("unsafe zip path traversal")
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() and target.stat().st_size == info.file_size:
                    continue
                with zf.open(info) as src, open(target, "wb") as out:
                    while True:
                        chunk = src.read(1024 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)
                try:
                    mtime = dt.datetime(*info.date_time).timestamp()
                    os.utime(target, (mtime, mtime))
                except Exception:
                    pass
                extracted += 1
            except Exception as exc:
                errors.append({
                    "Zip": str(zip_path),
                    "Entry": info.filename,
                    "Error": str(exc),
                })
    return extracted, errors


def inventory_files():
    rows = []
    for path in EXTRACT_DIR.rglob("*"):
        if path.is_file() and OUT_DIR not in path.parents:
            st = path.stat()
            rows.append({
                "Full path": str(path),
                "Extension": path.suffix.lower(),
                "Size": st.st_size,
                "Modified time": dt.datetime.fromtimestamp(st.st_mtime).isoformat(sep=" ", timespec="seconds"),
            })
    return rows


def service_from_path_text(path: Path, text: str = ""):
    blob = (str(path) + " " + text[:500]).lower()
    hits = [name for name, terms in SERVICES if any(term in blob for term in terms)]
    return "; ".join(dict.fromkeys(hits)) if hits else "Unknown"


def event_type_from_text(text: str):
    low = text.lower()
    checks = [
        ("Search query", ["searched for", "search query", "query"]),
        ("Email view/activity", ["gmail", "inbox", "subject:", "mail"]),
        ("Drive file activity", ["drive", "opened", "viewed", "download", "upload", "file"]),
        ("Security/account activity", ["login", "signed in", "password", "recovery", "session", "device"]),
        ("Business profile activity", ["business profile", "google my business"]),
        ("Device activity", ["iphone", "ios", "android", "device"]),
    ]
    for label, terms in checks:
        if any(term in low for term in terms):
            return label
    return "Dated record"


def parse_dt(value):
    if not value:
        return None
    value = str(value).strip()
    value = value.replace("Z", "+00:00")
    candidates = [value]
    if "." in value and "+" in value:
        candidates.append(value.split(".")[0] + "+" + value.split("+", 1)[1])
    for candidate in candidates:
        try:
            parsed = dt.datetime.fromisoformat(candidate)
            if parsed.tzinfo:
                parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
            return parsed
        except Exception:
            pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%b %d, %Y, %I:%M:%S %p", "%b %d, %Y %I:%M:%S %p",
        "%B %d, %Y, %I:%M:%S %p", "%B %d, %Y %I:%M:%S %p",
        "%b %d, %Y", "%B %d, %Y",
    ):
        try:
            return dt.datetime.strptime(value, fmt)
        except Exception:
            pass
    return None


def extract_dates(text):
    out = []
    for pat in DATE_PATTERNS:
        for m in pat.finditer(text):
            parsed = parse_dt(m.group(0))
            if parsed and START <= parsed <= END:
                out.append((parsed, m.group(0)))
            elif "2024" in m.group(0):
                # Date-only fallback when time parsing is messy.
                date_match = re.search(r"(2024[-/]0?4[-/](19|20|21|22|23|24|25|26))|((Apr|April)\s+(19|20|21|22|23|24|25|26),?\s+2024)", m.group(0), re.I)
                if date_match:
                    parsed = parse_dt(date_match.group(0))
                    if parsed and START.date() <= parsed.date() <= END.date():
                        out.append((parsed, m.group(0)))
    return out


def snippet(line, max_len=500):
    cleaned = re.sub(r"\s+", " ", html.unescape(str(line))).strip()
    return cleaned[:max_len]


def additional_metadata(text):
    ips = sorted(set(IP_RE.findall(text)))
    devices = sorted(set(m.group(0) for m in DEVICE_RE.finditer(text)))
    subject = ""
    for line in text.splitlines()[:30]:
        m = EMAIL_SUBJECT_RE.match(line)
        if m:
            subject = m.group(1)[:240]
            break
    queries = [m.group(1).strip() for m in QUERY_RE.finditer(text)]
    data = {}
    if subject:
        data["subject"] = subject
    if queries:
        data["queries"] = queries[:5]
    return ips, devices, json.dumps(data, ensure_ascii=False)


def add_event(events, timestamp, source, service, event_type, description, text):
    ips, devices, meta = additional_metadata(text)
    events.append({
        "Timestamp": timestamp.isoformat(sep=" ", timespec="seconds") if timestamp else "",
        "Source File": str(source),
        "Google Service": service,
        "Event Type": event_type,
        "Description": description,
        "Device": "; ".join(devices),
        "IP": "; ".join(ips),
        "Additional Metadata": meta,
    })


def scan_json(path, events, keyword_hits, gmail_terms):
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return False

    def walk(obj, parent=None):
        if isinstance(obj, dict):
            text_blob = " ".join(str(v) for v in obj.values() if isinstance(v, (str, int, float)))
            timestamp = None
            for key in ("time", "timestamp", "date", "startTime", "endTime", "createdTime", "modifiedTime", "viewedByMeTime"):
                if key in obj:
                    timestamp = parse_dt(obj.get(key))
                    if timestamp:
                        break
            if timestamp and START <= timestamp <= END:
                service = service_from_path_text(path, text_blob)
                title = str(obj.get("title") or obj.get("name") or obj.get("subject") or obj.get("description") or text_blob[:240])
                add_event(events, timestamp, path, service, event_type_from_text(text_blob), snippet(title), text_blob)
                if "gmail" in service.lower() or "mail" in str(path).lower():
                    for word in re.findall(r"[A-Za-z][A-Za-z0-9_.@-]{2,}", text_blob.lower()):
                        gmail_terms[word] += 1
            for v in obj.values():
                walk(v, obj)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, parent)

    walk(data)
    scan_text_lines(path, events, keyword_hits, gmail_terms, already_json=True)
    return True


def scan_sqlite(path, events, keyword_hits, gmail_terms):
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except Exception:
        return False
    try:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        for table in tables[:80]:
            try:
                cur = conn.execute(f"SELECT * FROM {table} LIMIT 2000")
                cols = [d[0] for d in cur.description]
                for row in cur.fetchall():
                    blob = " ".join(str(x) for x in row if x is not None)
                    for ts, raw in extract_dates(blob):
                        add_event(events, ts, path, service_from_path_text(path, blob), f"SQLite row: {table}", snippet(blob), blob)
                    keyword_scan(path, blob, keyword_hits)
            except Exception:
                continue
    finally:
        conn.close()
    return True


def keyword_scan(path, text, keyword_hits):
    low = text.lower()
    for kw in KEYWORDS:
        if kw.lower() in low:
            keyword_hits.append({
                "Keyword": kw,
                "Source File": str(path),
                "Snippet": snippet(text),
            })


def scan_mbox(path, events, keyword_hits, gmail_terms):
    try:
        with open(path, "rb") as f:
            for msg in email.iterators._structure([]):
                pass
    except Exception:
        pass
    count = 0
    try:
        with open(path, "rb") as f:
            current = []
            for raw in f:
                line = raw.decode("utf-8", errors="replace")
                if line.startswith("From ") and current:
                    process_mbox_message(path, "".join(current), events, keyword_hits, gmail_terms)
                    current = []
                    count += 1
                    if count > 200000:
                        break
                current.append(line)
            if current:
                process_mbox_message(path, "".join(current), events, keyword_hits, gmail_terms)
    except Exception:
        return False
    return True


def process_mbox_message(path, raw, events, keyword_hits, gmail_terms):
    keyword_scan(path, raw, keyword_hits)
    try:
        msg = email.message_from_string(raw, policy=email.policy.default)
        date_val = msg.get("Date", "")
        parsed = email.utils.parsedate_to_datetime(date_val) if date_val else None
        if parsed and parsed.tzinfo:
            parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
        if parsed and START <= parsed <= END:
            subject = msg.get("Subject", "")
            text = f"Subject: {subject} From: {msg.get('From','')} To: {msg.get('To','')} Date: {date_val}"
            add_event(events, parsed, path, "Gmail", "Email record", snippet(text), text)
            for word in re.findall(r"[A-Za-z][A-Za-z0-9_.@-]{2,}", text.lower()):
                gmail_terms[word] += 1
    except Exception:
        pass


def scan_text_lines(path, events, keyword_hits, gmail_terms, already_json=False):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if len(line) > 20000:
                    line = line[:20000]
                keyword_scan(path, line, keyword_hits)
                for ts, raw in extract_dates(line):
                    service = service_from_path_text(path, line)
                    add_event(events, ts, path, service, event_type_from_text(line), f"Line {i}: {snippet(line)}", line)
                if "gmail" in str(path).lower() or "mail" in str(path).lower():
                    for word in re.findall(r"[A-Za-z][A-Za-z0-9_.@-]{2,}", line.lower()):
                        gmail_terms[word] += 1
    except Exception:
        pass


def scan_files(inventory):
    events = []
    keyword_hits = []
    gmail_terms = Counter()
    indexed = []
    for idx, row in enumerate(inventory, 1):
        path = Path(row["Full path"])
        ext = path.suffix.lower()
        if ext not in TEXT_EXTS:
            continue
        if ext in MEDIA_EXTS:
            continue
        indexed.append({
            "Full path": str(path),
            "Extension": ext,
            "Size": row["Size"],
        })
        if ext == ".json":
            if scan_json(path, events, keyword_hits, gmail_terms):
                continue
        if ext in {".sqlite", ".sqlite3", ".db"}:
            if scan_sqlite(path, events, keyword_hits, gmail_terms):
                continue
        if ext == ".mbox":
            if scan_mbox(path, events, keyword_hits, gmail_terms):
                continue
        scan_text_lines(path, events, keyword_hits, gmail_terms)
    return events, keyword_hits, gmail_terms, indexed


def write_csv(path, rows, headers):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def build_clusters(events):
    parsed = []
    for e in events:
        ts = parse_dt(e.get("Timestamp"))
        if not ts:
            continue
        service = e.get("Google Service", "")
        if any(s.lower() in service.lower() for s in ["gmail", "drive", "account", "search"]):
            parsed.append((ts, e))
    parsed.sort(key=lambda x: x[0])
    clusters = []
    i = 0
    while i < len(parsed):
        start = parsed[i][0]
        window = []
        j = i
        while j < len(parsed) and (parsed[j][0] - start).total_seconds() <= 300:
            window.append(parsed[j])
            j += 1
        if len(window) >= 3:
            end = window[-1][0]
            services = sorted(set(w[1].get("Google Service", "") for w in window))
            clusters.append({
                "Start": start.isoformat(sep=" ", timespec="seconds"),
                "End": end.isoformat(sep=" ", timespec="seconds"),
                "Duration": str(end - start),
                "Number of events": len(window),
                "Services involved": "; ".join(services),
            })
        i += 1
    # De-duplicate identical clusters.
    seen = set()
    unique = []
    for c in clusters:
        key = (c["Start"], c["End"], c["Number of events"])
        if key not in seen:
            unique.append(c)
            seen.add(key)
    return unique


def findings(events, clusters, keyword_hits, gmail_terms, indexed, errors):
    service_counts = Counter(e["Google Service"] for e in events)
    event_type_counts = Counter(e["Event Type"] for e in events)
    keyword_counts = Counter(k["Keyword"] for k in keyword_hits)
    lines = []
    lines.append("# Google Takeout Forensic Timeline Findings\n")
    lines.append(f"Analysis window: {START} through {END} inclusive.\n")
    lines.append(f"Extracted/indexed folder: `{EXTRACT_DIR}`\n")
    lines.append(f"Indexed text-like files: {len(indexed)}\n")
    lines.append(f"Timeline events identified in window: {len(events)}\n")
    lines.append(f"Keyword hits: {len(keyword_hits)}\n")
    lines.append(f"Extraction errors: {len(errors)}\n")
    lines.append("\n## 1. Timeline Overview\n")
    if events:
        lines.append(f"Earliest event: {events[0]['Timestamp']}\n")
        lines.append(f"Latest event: {events[-1]['Timestamp']}\n")
    lines.append("\nService counts:\n")
    for service, count in service_counts.most_common():
        lines.append(f"- {service}: {count}\n")
    lines.append("\nEvent type counts:\n")
    for typ, count in event_type_counts.most_common():
        lines.append(f"- {typ}: {count}\n")
    lines.append("\n## 2. Significant Activity Between April 19-26\n")
    for e in events[:80]:
        lines.append(f"- {e['Timestamp']} | {e['Google Service']} | {e['Event Type']} | {e['Description']} | Source: `{e['Source File']}`\n")
    if len(events) > 80:
        lines.append(f"- Additional events are listed in `timeline.csv` ({len(events)} total rows).\n")
    lines.append("\n## 3. Gmail Activity\n")
    gmail_events = [e for e in events if "gmail" in e["Google Service"].lower() or "gmail" in e["Source File"].lower() or "mail" in e["Source File"].lower()]
    lines.append(f"Gmail-related timeline rows: {len(gmail_events)}\n")
    for e in gmail_events[:40]:
        lines.append(f"- {e['Timestamp']} | {e['Event Type']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## 4. Google Drive Activity\n")
    drive_events = [e for e in events if "drive" in e["Google Service"].lower() or "drive" in e["Source File"].lower()]
    lines.append(f"Drive-related timeline rows: {len(drive_events)}\n")
    for e in drive_events[:40]:
        lines.append(f"- {e['Timestamp']} | {e['Event Type']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## 5. Security/Account Activity\n")
    acct_events = [e for e in events if "account" in e["Google Service"].lower() or "security" in e["Event Type"].lower()]
    lines.append(f"Security/account-related timeline rows: {len(acct_events)}\n")
    for e in acct_events[:40]:
        lines.append(f"- {e['Timestamp']} | {e['Event Type']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## 6. Search Queries Recovered\n")
    query_events = [e for e in events if "search" in e["Event Type"].lower() or "search" in e["Google Service"].lower()]
    lines.append(f"Search-related timeline rows: {len(query_events)}\n")
    for e in query_events[:50]:
        lines.append(f"- {e['Timestamp']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## 7. File Access Recovered\n")
    file_events = [e for e in events if any(term in (e["Event Type"] + " " + e["Description"]).lower() for term in ["file", "drive", "download", "upload", "opened", "viewed"])]
    lines.append(f"File-access-like timeline rows: {len(file_events)}\n")
    for e in file_events[:50]:
        lines.append(f"- {e['Timestamp']} | {e['Google Service']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## 8. Device Information Recovered\n")
    device_events = [e for e in events if e["Device"] or e["IP"]]
    lines.append(f"Rows with device/browser/IP indicators: {len(device_events)}\n")
    for e in device_events[:50]:
        lines.append(f"- {e['Timestamp']} | Device: {e['Device']} | IP: {e['IP']} | Source: `{e['Source File']}`\n")
    lines.append("\n## 9. Activity Clusters\n")
    lines.append(f"Five-minute clusters with at least three relevant events: {len(clusters)}\n")
    for c in clusters[:40]:
        lines.append(f"- {c['Start']} to {c['End']} | {c['Number of events']} events | {c['Services involved']}\n")
    lines.append("\n## 10. Keyword Search Summary\n")
    for kw, count in keyword_counts.most_common():
        lines.append(f"- {kw}: {count}\n")
    lines.append("\n## 11. 500 Most Common Terms Found In Gmail Activity\n")
    for term, count in gmail_terms.most_common(500):
        lines.append(f"- {term}: {count}\n")
    lines.append("\n## 12. Gaps Or Limitations\n")
    lines.append("- This script indexes Takeout-exported records only. Absence of an event in Takeout is not proof that the event did not occur.\n")
    lines.append("- Some Google products export metadata but not full access logs, IP addresses, or session identifiers.\n")
    lines.append("- MBOX email records identify email messages in the archive, not necessarily message-open/view events unless Google exported separate activity records.\n")
    lines.append("- OCR is not performed here; media files are ignored unless metadata or adjacent exported records contain searchable text.\n")
    lines.append("- Native phone artifacts and provider logs should be used to confirm actor attribution, device identifiers, session data, and access method.\n")
    if errors:
        lines.append("- Extraction errors occurred. See `extraction_errors.csv`.\n")
    return "".join(lines)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    extraction_errors = []
    zip_rows = []
    for zip_path in sorted(ZIP_DIR.glob("*.zip")):
        print(f"Extracting/checking {zip_path.name}", flush=True)
        try:
            extracted, errors = safe_extract(zip_path, EXTRACT_DIR)
            zip_rows.append({"Zip": str(zip_path), "Extracted new files": extracted, "Errors": len(errors)})
            extraction_errors.extend(errors)
        except Exception as exc:
            extraction_errors.append({"Zip": str(zip_path), "Entry": "", "Error": str(exc)})
            zip_rows.append({"Zip": str(zip_path), "Extracted new files": 0, "Errors": 1})

    inventory = inventory_files()
    write_csv(OUT_DIR / "inventory.csv", inventory, ["Full path", "Extension", "Size", "Modified time"])
    write_csv(OUT_DIR / "extraction_summary.csv", zip_rows, ["Zip", "Extracted new files", "Errors"])
    write_csv(OUT_DIR / "extraction_errors.csv", extraction_errors, ["Zip", "Entry", "Error"])

    print(f"Inventory files: {len(inventory)}", flush=True)
    events, keyword_hits, gmail_terms, indexed = scan_files(inventory)
    events.sort(key=lambda e: e["Timestamp"])
    clusters = build_clusters(events)

    write_csv(OUT_DIR / "timeline.csv", events, ["Timestamp", "Source File", "Google Service", "Event Type", "Description", "Device", "IP", "Additional Metadata"])
    write_csv(OUT_DIR / "keyword_hits.csv", keyword_hits, ["Keyword", "Source File", "Snippet"])
    write_csv(OUT_DIR / "activity_clusters.csv", clusters, ["Start", "End", "Duration", "Number of events", "Services involved"])
    write_csv(OUT_DIR / "indexed_files.csv", indexed, ["Full path", "Extension", "Size"])
    write_csv(OUT_DIR / "gmail_common_terms.csv", [{"Term": t, "Count": c} for t, c in gmail_terms.most_common(500)], ["Term", "Count"])
    (OUT_DIR / "findings.md").write_text(findings(events, clusters, keyword_hits, gmail_terms, indexed, extraction_errors), encoding="utf-8")
    print(f"Outputs written to {OUT_DIR}", flush=True)
    print(f"Timeline events: {len(events)}", flush=True)
    print(f"Keyword hits: {len(keyword_hits)}", flush=True)
    print(f"Clusters: {len(clusters)}", flush=True)
    print(f"Extraction errors: {len(extraction_errors)}", flush=True)


if __name__ == "__main__":
    main()
