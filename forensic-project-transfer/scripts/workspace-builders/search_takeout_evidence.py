import csv
import ipaddress
import re
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

OUT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024")
EXTRACT_DIR = OUT_DIR / "Extracted Priority Text"
EXTRACT_CSV = OUT_DIR / "extracted_priority_files.csv"
INVENTORY_CSV = OUT_DIR / "takeout_zip_inventory.csv"
HITS_CSV = OUT_DIR / "takeout_evidence_hits.csv"
REPORT_MD = OUT_DIR / "April2024_Takeout_Access_Audit_Report.md"

CASE_TERMS = [
    "HELO Payment Services LLC EIN.pdf",
    "HeloPaymentServicesVoidedCheck.png",
    "EIN",
    "IRS",
    "CP 575",
    "147C",
    "bank statement",
    "financial statement",
    "business names",
    "Helo Payment Services",
    "Keenlane",
    "Go Fingerprinting",
    "Navy Federal",
    "Payanywhere",
    "Payments Hub",
    "DocuSign",
    "DoorDash",
    "DecisionLogic",
    "Trustfi",
    "Virtue Capital",
    "LCF Group",
    "Everest Business Funding",
    "Port Orange",
    "Summerfield",
    "iPhone",
    "iOS",
    "Elijah",
    "Robin",
    "robinhurd1@gmail.com",
]
ACTION_TERMS = ["view", "viewed", "download", "downloaded", "login", "sign-in", "signed in", "access", "opened", "shared", "export"]
DEVICE_TERMS = ["iphone", "ios", "safari", "chrome", "device", "mobile", "elijah", "robin"]
SERVICE_PATTERNS = [
    ("Access Log Activity", "AccountAccess"),
    ("My Activity", "UnknownButRelevant"),
    ("Alerts", "GoogleSecurityAlert"),
    ("Google Account", "AccountAccess"),
    ("Drive", "DriveView"),
    ("Google Business Profile", "GoogleBusinessProfileAccess"),
    ("Android Device Configuration", "DeviceLogin"),
    ("Chrome", "UnknownButRelevant"),
    ("Photos", "ScreenshotMetadata"),
]
DATE_RE = re.compile(r"2024[-/](?:0?4)[-/](?:19|20|21|22|23|24|25|26)|(?:Apr(?:il)?\.?\s+)(?:19|20|21|22|23|24|25|26),?\s+2024|(?:19|20|21|22|23|24|25|26)\s+Apr(?:il)?\.?\s+2024", re.I)
ISO_TS_RE = re.compile(r"2024-04-(?:19|20|21|22|23|24|25|26)[T ][0-9:.+-Z]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_extract_rows():
    if not EXTRACT_CSV.exists():
        return {}
    with EXTRACT_CSV.open(newline="", encoding="utf-8-sig") as f:
        return {row["OutputPath"]: row for row in csv.DictReader(f)}


def extended_path(path):
    resolved = str(path.resolve())
    if resolved.startswith("\\\\?\\"):
        return resolved
    return "\\\\?\\" + resolved


def read_text(path):
    with open(extended_path(path), "rb") as f:
        data = f.read()
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc, errors="replace")
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def service_and_category(path, text, terms):
    combined = f"{path}\n{text[:1000]}"
    for service, category in SERVICE_PATTERNS:
        if service.lower() in combined.lower():
            if service == "Drive" and any(t in terms for t in ["download", "downloaded"]):
                return service, "DriveDownload"
            return service, category
    return "", "UnknownButRelevant"


def classify(terms, path):
    low_terms = {t.lower() for t in terms}
    low_path = str(path).lower()
    if {"iphone", "ios", "elijah", "robin"} & low_terms:
        return "RobinElijahReference"
    if {"ein", "irs", "cp 575", "147c", "bank statement", "financial statement", "business names"} & low_terms:
        return "FinancialDocumentAccess"
    if any(term.lower() in low_path for term in ["google business profile"]):
        return "GoogleBusinessProfileAccess"
    if "drive" in low_path and any(t in low_terms for t in ["download", "downloaded"]):
        return "DriveDownload"
    if "drive" in low_path:
        return "DriveView"
    if any(t in low_terms for t in ["iphone", "ios", "safari", "chrome", "device", "mobile"]):
        return "DeviceLogin"
    return "UnknownButRelevant"


def timestamp_eastern(raw):
    if not raw:
        return ""
    cleaned = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("UTC"))
        return dt.astimezone(ZoneInfo("America/New_York")).isoformat()
    except ValueError:
        return ""


def valid_ips(text):
    out = []
    for match in IP_RE.findall(text):
        try:
            ipaddress.ip_address(match)
            out.append(match)
        except ValueError:
            pass
    return out


def snippet(text, start, end):
    left = max(0, start - 180)
    right = min(len(text), end + 180)
    return re.sub(r"\s+", " ", text[left:right]).strip()


def find_hits(path, meta):
    text = read_text(path)
    low = text.lower()
    path_low = str(path).lower()
    terms = [t for t in CASE_TERMS + ACTION_TERMS + DEVICE_TERMS if t.lower() in low or t.lower() in path_low]
    date_matches = list(DATE_RE.finditer(text)) + list(ISO_TS_RE.finditer(text))
    relevant_without_date = terms and any(t.lower() in path_low for t in CASE_TERMS)
    if not date_matches and not relevant_without_date:
        return []

    hits = []
    windows = date_matches[:200] if date_matches else [None]
    for m in windows:
        if m:
            snip = snippet(text, m.start(), m.end())
            raw_ts = m.group(0)
        else:
            snip = snippet(text, 0, min(len(text), 500))
            raw_ts = ""
        snip_low = snip.lower()
        local_terms = [t for t in CASE_TERMS + ACTION_TERMS + DEVICE_TERMS if t.lower() in snip_low or t.lower() in path_low]
        ips = valid_ips(snip)
        service, default_category = service_and_category(path, snip, local_terms)
        category = classify(local_terms, path) if local_terms else default_category
        confidence = "High" if raw_ts and (local_terms or ips) else ("Medium" if raw_ts or local_terms else "Low")
        hits.append(
            {
                "SourceFile": str(path),
                "SourceZip": meta.get("SourceZip", ""),
                "EntryPath": meta.get("EntryPath", ""),
                "TimestampRaw": raw_ts,
                "TimestampEastern": timestamp_eastern(raw_ts),
                "Service": service or meta.get("PriorityService", ""),
                "EvidenceCategory": category,
                "MatchedTerms": "; ".join(dict.fromkeys(local_terms)),
                "DeviceInfo": "; ".join(t for t in local_terms if t.lower() in [d.lower() for d in DEVICE_TERMS]),
                "IPAddress": "; ".join(dict.fromkeys(ips)),
                "Location": "; ".join(t for t in local_terms if t in ["Port Orange", "Summerfield"]),
                "FileOrDocumentName": "; ".join(t for t in local_terms if "." in t or t in ["EIN", "IRS", "bank statement", "financial statement", "business names"]),
                "Action": "; ".join(t for t in local_terms if t.lower() in [a.lower() for a in ACTION_TERMS]),
                "Snippet": snip[:1000],
                "Confidence": confidence,
                "Notes": "Automated text hit; review source context before relying on it.",
            }
        )
    return hits


def write_report(hits, extract_rows):
    scanned = []
    services = {}
    if INVENTORY_CSV.exists():
        with INVENTORY_CSV.open(newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                scanned.append(row["ZipFile"])
                for service in row.get("PriorityService", "").split("; "):
                    if service:
                        services[service] = services.get(service, 0) + 1
    scanned = sorted(set(scanned))
    high = [h for h in hits if h["Confidence"] == "High"]
    medium_low = [h for h in hits if h["Confidence"] != "High"]
    timeline = sorted([h for h in hits if h["TimestampRaw"]], key=lambda h: h["TimestampRaw"])[:100]

    def bullet_hits(items, limit=20):
        if not items:
            return "- None identified by the automated search.\n"
        lines = []
        for h in items[:limit]:
            ts = h["TimestampEastern"] or h["TimestampRaw"] or "No timestamp"
            lines.append(f"- {ts} | {h['Service']} | {h['EvidenceCategory']} | {h['MatchedTerms']} | {h['EntryPath']}")
        return "\n".join(lines) + "\n"

    report = [
        "# April 2024 Takeout Access Audit Report",
        "",
        "## 1. Scope and chain-of-custody note",
        "This review scanned local Google Takeout ZIP files without network access. Original ZIP files were not modified, renamed, deleted, moved, or recompressed. Phase 1 used ZIP manifests only. Phase 2 extracted only allowlisted text/metadata files from priority services within the configured size limits.",
        "",
        "## 2. ZIP files scanned",
        "\n".join(f"- {z}" for z in scanned) if scanned else "- None found in inventory.",
        "",
        "## 3. Priority Takeout services found",
        "\n".join(f"- {k}: {v} entries" for k, v in sorted(services.items())) if services else "- No priority services found.",
        "",
        "## 4. Extracted priority files",
        f"- Extracted files listed in `{EXTRACT_CSV}`.",
        f"- Count: {len(extract_rows)}",
        "",
        "## 5. Evidence timeline from April 19-26, 2024",
        bullet_hits(timeline, 40),
        "## 6. High-confidence findings",
        bullet_hits(high, 30),
        "## 7. Medium/low-confidence findings",
        bullet_hits(medium_low, 30),
        "## 8. Items supporting unauthorized access via Elijah's iPhone or iOS device",
        bullet_hits([h for h in hits if h["EvidenceCategory"] in ("RobinElijahReference", "DeviceLogin") or "iPhone" in h["MatchedTerms"] or "iOS" in h["MatchedTerms"]], 30),
        "## 9. Items showing Drive/Google Business/Profile/Gmail access",
        bullet_hits([h for h in hits if any(s in h["Service"] + h["EvidenceCategory"] + h["EntryPath"] for s in ["Drive", "Google Business Profile", "Gmail", "Mail"])], 30),
        "## 10. Items involving business or financial records",
        bullet_hits([h for h in hits if h["EvidenceCategory"] in ("FinancialDocumentAccess", "BusinessRecordAccess")], 30),
        "## 11. Gaps: what Takeout does not prove",
        "- Takeout may omit detailed IP/device records for some activity or retain them only for limited periods.",
        "- Text hits show where relevant terms appear, but they do not by themselves prove who physically used a device.",
        "- Drive or account activity may require corroboration from Google security logs, device backups, browser history, screenshots metadata, or legal-process records.",
        "",
        "## 12. Next recommended files/parts to download",
        "- Google Account security events and Access Log Activity exports covering April 19-26, 2024.",
        "- My Activity for Drive, Chrome, Search, and device activity.",
        "- Google Business Profile management/activity exports.",
        "- Google Photos metadata for screenshots during April 19-26, 2024, without photo binaries unless separately approved.",
        "- Device backups or iOS Screen Time/browser history from the relevant iPhone, if legally available.",
    ]
    REPORT_MD.write_text("\n".join(report) + "\n", encoding="utf-8")


def main():
    meta_by_path = load_extract_rows()
    hits = []
    for p in sorted(EXTRACT_DIR.rglob("*")) if EXTRACT_DIR.exists() else []:
        if p.is_file():
            hits.extend(find_hits(p, meta_by_path.get(str(p), {})))

    with HITS_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        fields = [
            "SourceFile",
            "SourceZip",
            "EntryPath",
            "TimestampRaw",
            "TimestampEastern",
            "Service",
            "EvidenceCategory",
            "MatchedTerms",
            "DeviceInfo",
            "IPAddress",
            "Location",
            "FileOrDocumentName",
            "Action",
            "Snippet",
            "Confidence",
            "Notes",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(hits)

    write_report(hits, list(meta_by_path.values()))
    print(f"Evidence hits: {len(hits)}")
    print(f"Evidence CSV: {HITS_CSV}")
    print(f"Report: {REPORT_MD}")


if __name__ == "__main__":
    main()
