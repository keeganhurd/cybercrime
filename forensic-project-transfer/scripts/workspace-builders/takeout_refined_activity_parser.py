import csv
import datetime as dt
import email
import email.policy
import html
import json
import re
from pathlib import Path
from collections import Counter


ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout")
OUT = ROOT.parent / "_forensic_outputs"
START = dt.datetime(2024, 4, 19, 0, 0, 0)
END = dt.datetime(2024, 4, 26, 23, 59, 59)

KEYWORDS = [
    "Jonathan", "Braese", "Breas", "Jonathan Brease", "keeganhurd@gmail.com",
    "GoFingerprinting", "Go Fingerprinting", "Helo", "Merchant", "Authorize.net",
    "Stripe", "Bank", "Banking", "Statement", "Checking", "Savings", "Tax",
    "EIN", "Password", "Drive", "Gmail", "Inbox", "Business",
    "Google Business", "Google My Business", "Mom", "Robin", "Elijah",
]

MONTHS = {
    "Jan": 1, "January": 1, "Feb": 2, "February": 2, "Mar": 3, "March": 3,
    "Apr": 4, "April": 4, "May": 5, "Jun": 6, "June": 6, "Jul": 7, "July": 7,
    "Aug": 8, "August": 8, "Sep": 9, "Sept": 9, "September": 9,
    "Oct": 10, "October": 10, "Nov": 11, "November": 11, "Dec": 12, "December": 12,
}

DATE_RE = re.compile(
    r"\b("
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|"
    r"Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
    r")\s+(\d{1,2}),\s+(2024),\s+(\d{1,2}):(\d{2}):(\d{2})\s*(AM|PM)\s*(EDT|EST)?",
    re.I,
)
ISO_RE = re.compile(r"2024-04-(19|20|21|22|23|24|25|26)T?\s*([0-9:.+-Z]*)?", re.I)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DEVICE_RE = re.compile(r"\b(iPhone|iOS|Android|Windows|Mac(?:intosh)?|Chrome|Safari|Firefox|Edge|Pixel|iPad|PC)\b", re.I)


def clean(s):
    s = re.sub(r"<script.*?</script>", " ", s, flags=re.I | re.S)
    s = re.sub(r"<style.*?</style>", " ", s, flags=re.I | re.S)
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = s.replace("\u202f", " ").replace("\xa0", " ")
    return re.sub(r"[ \t\r\f\v]+", " ", s).strip()


def parse_google_date(text):
    text = text.replace("\u202f", " ").replace("\xa0", " ")
    m = DATE_RE.search(text)
    if not m:
        return None
    mon, day, year, hour, minute, sec, ap, tz = m.groups()
    hour = int(hour)
    if ap.upper() == "PM" and hour != 12:
        hour += 12
    if ap.upper() == "AM" and hour == 12:
        hour = 0
    return dt.datetime(int(year), MONTHS[mon[:3].title()], int(day), hour, int(minute), int(sec))


def parse_iso(value):
    value = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(value)
        if parsed.tzinfo:
            # Store in UTC without tz marker for sortable CSV. Source text remains in description.
            parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        return None


def service_from_path(path):
    parts = [p.lower() for p in path.parts]
    if "my activity" in parts:
        try:
            return path.parts[parts.index("my activity") + 1]
        except Exception:
            return "My Activity"
    for service in ["Access Log Activity", "Google Business Profile", "Google Account", "Drive", "Mail", "Chrome", "Google Photos"]:
        if service.lower() in str(path).lower():
            return service
    return "Unknown"


def classify(desc, service):
    low = (desc + " " + service).lower()
    if "searched for" in low:
        return "Search"
    if "visited" in low:
        return "Visited/Open"
    if "used" in low:
        return "Used service"
    if "viewed" in low:
        return "Viewed"
    if "createTime".lower() in low or "updateTime".lower() in low:
        return "Metadata timestamp"
    return "Activity"


def meta(text):
    ips = sorted(set(IP_RE.findall(text)))
    dev = sorted(set(m.group(0) for m in DEVICE_RE.finditer(text)))
    terms = [kw for kw in KEYWORDS if kw.lower() in text.lower()]
    return "; ".join(dev), "; ".join(ips), "; ".join(terms)


def event(ts, source, service, typ, desc, raw):
    device, ip, terms = meta(raw)
    return {
        "Timestamp": ts.isoformat(sep=" ", timespec="seconds"),
        "Source File": str(source),
        "Google Service": service,
        "Event Type": typ,
        "Description": desc[:700],
        "Device": device,
        "IP": ip,
        "Additional Metadata": terms,
    }


def parse_myactivity_html(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r'(?=<div class="outer-cell\b)', text)
    events = []
    for block in blocks:
        if "2024" not in block:
            continue
        cleaned = clean(block)
        ts = parse_google_date(cleaned)
        if not ts or not (START <= ts <= END):
            continue
        lines = [x.strip() for x in cleaned.splitlines() if x.strip()]
        service = service_from_path(path)
        desc = ""
        if lines:
            # Usually first line is product and second is the activity text.
            useful = [x for x in lines if not x.startswith("Products:") and not x.startswith("Why is this here?")]
            desc = " | ".join(useful[:4])
        events.append(event(ts, path, service, classify(desc, service), desc, cleaned))
    return events


def parse_business_json(path):
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return out
    for key in ("createTime", "updateTime", "expirationTime"):
        for m in re.finditer(rf'"{key}"\s*:\s*"([^"]+)"', text):
            ts = parse_iso(m.group(1))
            if ts and START <= ts <= END:
                out.append(event(ts, path, "Google Business Profile", f"{key} metadata", f'{key}: {m.group(1)}', text[:2000]))
    return out


def parse_access_log(path):
    out = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            ts_raw = row.get("Activity Timestamp", "")
            if not ts_raw.startswith("2024-04-"):
                continue
            ts = parse_iso(ts_raw.replace(" UTC", "+00:00"))
            if not ts or not (START <= ts <= END):
                continue
            product = row.get("Product Name", "")
            sub = row.get("Sub-Product Name", "")
            desc = f"{product} {sub} {row.get('Activity Type','')}".strip()
            raw = " ".join(str(v) for v in row.values())
            out.append({
                "Timestamp": ts.isoformat(sep=" ", timespec="seconds"),
                "Source File": str(path),
                "Google Service": product or "Access Log Activity",
                "Event Type": "Access log row",
                "Description": desc,
                "Device": row.get("User Agent String", ""),
                "IP": row.get("IP Address", ""),
                "Additional Metadata": f"Country={row.get('Activity Country','')}; Region={row.get('Activity Region','')}; City={row.get('Activity City','')}; GmailChannel={row.get('Gmail Access Channel','')}",
            })
    return out


def parse_mail_mbox_subjects(path):
    out = []
    current = []
    count = 0
    with path.open("rb") as f:
        for raw in f:
            line = raw.decode("utf-8", errors="replace")
            if line.startswith("From ") and current:
                out.extend(process_msg(path, "".join(current)))
                current = []
                count += 1
            current.append(line)
        if current:
            out.extend(process_msg(path, "".join(current)))
    return out


def process_msg(path, raw):
    try:
        msg = email.message_from_string(raw, policy=email.policy.default)
        parsed = email.utils.parsedate_to_datetime(msg.get("Date", ""))
        if parsed.tzinfo:
            parsed = parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)
        if not (START <= parsed <= END):
            return []
        desc = f"Subject: {msg.get('Subject','')} | From: {msg.get('From','')} | To: {msg.get('To','')}"
        return [event(parsed, path, "Gmail", "Email message in archive", desc, desc)]
    except Exception:
        return []


def parse_account_login_coverage(path):
    if not path.exists():
        return {"source": str(path), "rows": 0, "min": "", "max": "", "window_rows": 0}
    text = path.read_text(encoding="utf-8", errors="replace")
    dated = []
    window_rows = 0
    for row in re.findall(r"<tr>(.*?)</tr>", text, flags=re.I | re.S):
        cells = [clean(cell) for cell in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, flags=re.I | re.S)]
        if not cells or not re.match(r"\d{4}-\d{2}-\d{2}\b", cells[0]):
            continue
        dated.append(cells[0])
        if re.match(r"2024-04-(19|20|21|22|23|24|25|26)\b", cells[0]):
            window_rows += 1
    return {
        "source": str(path),
        "rows": len(dated),
        "min": min(dated) if dated else "",
        "max": max(dated) if dated else "",
        "window_rows": window_rows,
    }


def keyword_hits_in_relevant_files(paths):
    rows = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for kw in KEYWORDS:
            idx = text.lower().find(kw.lower())
            if idx >= 0:
                start = max(0, idx - 180)
                end = min(len(text), idx + 320)
                rows.append({"Keyword": kw, "Source File": str(path), "Snippet": clean(text[start:end])[:500]})
    return rows


def write_csv(path, rows, headers):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def clusters(events):
    parsed = [(dt.datetime.fromisoformat(e["Timestamp"]), e) for e in events]
    parsed.sort(key=lambda x: x[0])
    out = []
    for i, (start, _) in enumerate(parsed):
        win = []
        j = i
        while j < len(parsed) and (parsed[j][0] - start).total_seconds() <= 300:
            win.append(parsed[j])
            j += 1
        if len(win) >= 3:
            end = win[-1][0]
            out.append({
                "Start": start.isoformat(sep=" ", timespec="seconds"),
                "End": end.isoformat(sep=" ", timespec="seconds"),
                "Duration": str(end - start),
                "Number of events": len(win),
                "Services involved": "; ".join(sorted(set(x[1]["Google Service"] for x in win))),
            })
    uniq = []
    seen = set()
    for row in out:
        key = (row["Start"], row["End"], row["Number of events"], row["Services involved"])
        if key not in seen:
            uniq.append(row)
            seen.add(key)
    return uniq


def findings(events, access_events, myactivity_events, mail_events, keyword_hits, clus, account_coverage):
    service_counts = Counter(e["Google Service"] for e in events)
    lines = []
    lines.append("# Refined Google Takeout Activity Findings\n\n")
    lines.append(f"Window: {START} through {END} inclusive.\n\n")
    lines.append("## Bottom Line\n")
    lines.append(f"- Total refined timeline rows: {len(events)}\n")
    lines.append(f"- My Activity rows in window: {len(myactivity_events)}\n")
    lines.append(f"- Access Log Activity rows in window: {len(access_events)}\n")
    lines.append(f"- Gmail message records dated in window: {len(mail_events)}\n")
    lines.append(f"- Five-minute clusters: {len(clus)}\n\n")
    lines.append("## Service Counts\n")
    for service, count in service_counts.most_common():
        lines.append(f"- {service}: {count}\n")
    lines.append("\n## Significant Activity\n")
    for e in events[:120]:
        lines.append(f"- {e['Timestamp']} | {e['Google Service']} | {e['Event Type']} | {e['Description']} | Source: `{e['Source File']}`\n")
    if len(events) > 120:
        lines.append(f"- Additional rows are in `timeline_refined.csv`.\n")
    lines.append("\n## Gmail Activity\n")
    gmail = [e for e in events if "gmail" in e["Google Service"].lower()]
    for e in gmail[:80]:
        lines.append(f"- {e['Timestamp']} | {e['Event Type']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## Drive Activity\n")
    drive = [e for e in events if "drive" in e["Google Service"].lower()]
    for e in drive[:80]:
        lines.append(f"- {e['Timestamp']} | {e['Event Type']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## Search Queries Recovered\n")
    search = [e for e in events if "search" in e["Google Service"].lower() or e["Event Type"] == "Search"]
    for e in search[:80]:
        lines.append(f"- {e['Timestamp']} | {e['Description']} | Source: `{e['Source File']}`\n")
    lines.append("\n## Access Log Activity\n")
    if access_events:
        for e in access_events:
            lines.append(f"- {e['Timestamp']} | {e['Google Service']} | IP {e['IP']} | Device {e['Device']} | Source: `{e['Source File']}`\n")
    else:
        lines.append("- No Access Log Activity rows dated April 19-26, 2024 were found. The exported Access Log Activity CSV date range observed was May-June 2026, so it does not confirm or refute April 2024 access.\n")
    lines.append("\n## Google Account Login/Subscriber Coverage\n")
    if account_coverage["rows"]:
        lines.append(f"- Google Account SubscriberInfo contains {account_coverage['rows']} dated login-style rows, with observed date coverage from {account_coverage['min']} through {account_coverage['max']}.\n")
        lines.append(f"- Rows dated April 19-26, 2024 in that SubscriberInfo login-style table: {account_coverage['window_rows']}.\n")
        lines.append(f"- Source: `{account_coverage['source']}`\n")
    else:
        lines.append(f"- No dated Google Account SubscriberInfo login-style rows were parsed from `{account_coverage['source']}`.\n")
    lines.append("\n## Keyword Hits In My Activity Files\n")
    for row in keyword_hits[:120]:
        lines.append(f"- {row['Keyword']} | {row['Snippet']} | Source: `{row['Source File']}`\n")
    lines.append("\n## Clusters\n")
    for c in clus[:80]:
        lines.append(f"- {c['Start']} to {c['End']} | {c['Number of events']} events | {c['Services involved']}\n")
    lines.append("\n## Gaps And Limitations\n")
    lines.append("- Takeout My Activity can show searches, visits, service use, and some product activity, but it may not include full IP/device/session data for historical activity.\n")
    lines.append("- Access Log Activity was present but did not contain April 19-26, 2024 rows in this export.\n")
    lines.append("- Gmail MBOX records show emails present/delivered in the archive, not necessarily that a message was opened by a specific person or device.\n")
    lines.append("- Drive files present in Takeout show account contents, but do not by themselves prove view/download activity unless paired with My Activity or access logs.\n")
    lines.append("- No legal conclusions or actor attribution are made here.\n")
    return "".join(lines)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    myactivity_events = []
    myactivity_files = list((ROOT / "My Activity").rglob("MyActivity.html"))
    for path in myactivity_files:
        myactivity_events.extend(parse_myactivity_html(path))

    business_events = []
    for path in (ROOT / "Google Business Profile").rglob("*.json"):
        business_events.extend(parse_business_json(path))

    access_path = ROOT / "Access Log Activity" / "Activities - A list of Google services accessed by.csv"
    access_events = parse_access_log(access_path) if access_path.exists() else []
    account_coverage = parse_account_login_coverage(ROOT / "Google Account" / "keeganhurd.SubscriberInfo.html")

    mail_events = []
    for path in (ROOT / "Mail").rglob("*.mbox"):
        mail_events.extend(parse_mail_mbox_subjects(path))

    all_events = myactivity_events + business_events + access_events + mail_events
    all_events.sort(key=lambda e: e["Timestamp"])
    clus = clusters(all_events)
    kw_hits = keyword_hits_in_relevant_files(myactivity_files)

    headers = ["Timestamp", "Source File", "Google Service", "Event Type", "Description", "Device", "IP", "Additional Metadata"]
    write_csv(OUT / "timeline_refined.csv", all_events, headers)
    write_csv(OUT / "myactivity_events_apr19_26.csv", myactivity_events, headers)
    write_csv(OUT / "access_log_apr19_26.csv", access_events, headers)
    write_csv(OUT / "gmail_messages_apr19_26.csv", mail_events, headers)
    write_csv(OUT / "activity_clusters_refined.csv", clus, ["Start", "End", "Duration", "Number of events", "Services involved"])
    write_csv(OUT / "keyword_hits_myactivity.csv", kw_hits, ["Keyword", "Source File", "Snippet"])
    (OUT / "findings_refined.md").write_text(findings(all_events, access_events, myactivity_events, mail_events, kw_hits, clus, account_coverage), encoding="utf-8")
    print(f"Refined timeline rows: {len(all_events)}")
    print(f"My Activity rows: {len(myactivity_events)}")
    print(f"Access log rows: {len(access_events)}")
    print(f"Gmail message records: {len(mail_events)}")
    print(f"Clusters: {len(clus)}")
    print(f"Outputs: {OUT}")


if __name__ == "__main__":
    main()
