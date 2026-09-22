import csv
import re
from collections import defaultdict
from pathlib import Path

BASE = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024")
INVENTORY_CSV = BASE / "takeout_zip_inventory.csv"
EXTRACTED_CSV = BASE / "extracted_priority_files.csv"
HITS_CSV = BASE / "takeout_evidence_hits.csv"
TRIAGE_DIR = BASE / "Triage"

CRITICAL_CSV = TRIAGE_DIR / "Critical_Evidence_Triage.csv"
TIER1_CSV = TRIAGE_DIR / "Tier1_Direct_Access_Findings.csv"
TIER2_CSV = TRIAGE_DIR / "Tier2_Circumstantial_Findings.csv"
TIER3_CSV = TRIAGE_DIR / "Financial_Document_Context.csv"
NOISE_CSV = TRIAGE_DIR / "Noise_Excluded.csv"
COVERAGE_CSV = TRIAGE_DIR / "Service_Coverage_Summary.csv"
MISSING_MD = TRIAGE_DIR / "Missing_Expected_Evidence.md"
REPORT_MD = TRIAGE_DIR / "April2024_Strict_Forensic_Triage_Report.md"

EXPECTED_SERVICES = [
    "Access Log Activity",
    "My Activity",
    "Google Account",
    "Alerts",
    "Drive",
    "Google Business Profile",
    "Android Device Configuration Service",
    "Chrome",
    "Google Photos metadata",
]

TRIAGE_FIELDS = [
    "Rank",
    "RelevanceTier",
    "TimestampEastern",
    "Service",
    "EvidenceCategory",
    "Action",
    "DeviceInfo",
    "IPAddress",
    "Location",
    "FileOrDocumentName",
    "MatchedTerms",
    "SourceFile",
    "SourceZip",
    "EntryPath",
    "Snippet",
    "WhyItMatters",
    "SupportsUnauthorizedAccess",
    "SupportsElijahIphoneTheory",
    "SupportsFinancialDocumentAccess",
    "GapsOrLimitations",
    "RecommendedFollowUp",
]

FINANCIAL_TERMS = [
    "ein",
    "irs",
    "cp 575",
    "147c",
    "bank statement",
    "financial statement",
    "business names",
    "helo payment services",
    "keenlane",
    "go fingerprinting",
    "navy federal",
    "payanywhere",
    "payments hub",
    "docusign",
    "doordash",
    "decisionlogic",
    "trustfi",
    "virtue capital",
    "lcf group",
    "everest business funding",
]

DEVICE_TERMS = ["iphone", "ios", "elijah", "robin", "safari", "mobile device", "ip address"]
DIRECT_ACCESS_TERMS = [
    "sign-in",
    "signed in",
    "login",
    "logged in",
    "access log",
    "ip address",
    "device",
    "security alert",
    "recovery",
    "2-step",
    "password",
    "downloaded",
    "google business profile",
]
GENERIC_NOISE_ACTIONS = {"view", "viewed", "access"}


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def norm(text):
    return (text or "").lower()


def split_terms(text):
    return [t.strip() for t in (text or "").split(";") if t.strip()]


def date_in_window(row):
    combined = " ".join([row.get("TimestampRaw", ""), row.get("TimestampEastern", ""), row.get("Snippet", "")])
    return bool(
        re.search(r"2024-04-(19|20|21|22|23|24|25|26)\b", combined)
        or re.search(r"Apr(?:il)?\.?\s+(19|20|21|22|23|24|25|26),?\s+2024", combined, re.I)
    )


def service_tokens(row):
    text = " ".join([row.get("Service", ""), row.get("EntryPath", ""), row.get("SourceFile", "")]).lower()
    found = set()
    if "access log activity" in text:
        found.add("Access Log Activity")
    if "my activity" in text:
        found.add("My Activity")
    if "google account" in text:
        found.add("Google Account")
    if "alerts" in text:
        found.add("Alerts")
    if "drive" in text:
        found.add("Drive")
    if "google business profile" in text:
        found.add("Google Business Profile")
    if "android device configuration" in text:
        found.add("Android Device Configuration Service")
    if "chrome" in text:
        found.add("Chrome")
    if "photos" in text:
        found.add("Google Photos metadata")
    return found


def contains_any(text, terms):
    low = norm(text)
    return any(t in low for t in terms)


def source_context(row):
    path = Path(row.get("SourceFile", ""))
    if not path.exists() or path.is_dir():
        return ""
    try:
        with path.open("rb") as f:
            data = f.read(256 * 1024)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def score_and_classify(row):
    combined = " ".join(
        [
            row.get("Service", ""),
            row.get("EvidenceCategory", ""),
            row.get("Action", ""),
            row.get("DeviceInfo", ""),
            row.get("IPAddress", ""),
            row.get("Location", ""),
            row.get("FileOrDocumentName", ""),
            row.get("MatchedTerms", ""),
            row.get("EntryPath", ""),
            row.get("Snippet", ""),
        ]
    )
    low = norm(combined)
    services = service_tokens(row)
    in_window = date_in_window(row)
    has_ip = bool(row.get("IPAddress", "").strip()) or "ip address" in low
    has_device = contains_any(low, DEVICE_TERMS) or bool(row.get("DeviceInfo", "").strip())
    has_financial = contains_any(low, FINANCIAL_TERMS)
    has_direct_access = contains_any(low, DIRECT_ACCESS_TERMS)
    has_drive_access = "Drive" in services and contains_any(low, ["viewed", "downloaded", "opened", "activity", "access"])
    has_gbp_access = "Google Business Profile" in services and contains_any(low, ["viewed", "edited", "access", "manager", "owner", "business profile"])
    security_service = bool(services & {"Access Log Activity", "Google Account", "Alerts"})
    generic_my_activity = services == {"My Activity"} and not has_device and not has_financial and not has_drive_access and not has_gbp_access
    only_generic_terms = set(t.lower() for t in split_terms(row.get("MatchedTerms", ""))).issubset(GENERIC_NOISE_ACTIONS)

    score = 0
    if in_window:
        score += 25
    if security_service:
        score += 35
    if has_ip:
        score += 25
    if has_device:
        score += 20
    if has_drive_access or has_gbp_access:
        score += 20
    if has_financial:
        score += 10
    if has_direct_access:
        score += 10
    if generic_my_activity and only_generic_terms:
        score -= 30

    if in_window and (security_service or has_ip or (has_device and has_direct_access) or has_drive_access or has_gbp_access):
        tier = "Tier 1"
    elif in_window and (has_device or has_financial or has_drive_access or has_gbp_access or contains_any(low, ["screenshot", "robin", "elijah"])):
        tier = "Tier 2"
    elif has_financial:
        tier = "Tier 3"
    else:
        tier = "Noise"

    if tier == "Tier 1":
        why = "Direct or service-level access evidence during April 19-26, 2024."
        unauth = "Potentially, if the access was not performed by the account owner; corroborate with device/IP ownership."
    elif tier == "Tier 2":
        why = "Strong circumstantial April 19-26 context tied to device/person/service/sensitive document themes."
        unauth = "Circumstantial only; does not independently identify the actor."
    elif tier == "Tier 3":
        why = "Financial or business document context relevant to what may have been sought or accessed."
        unauth = "No direct access proof in this row."
    else:
        why = "Keyword-only or generic activity that does not materially prove access, device use, or document access."
        unauth = "No."

    return {
        "tier": tier,
        "score": score,
        "why": why,
        "supports_unauthorized": unauth,
        "supports_elijah": "Yes" if contains_any(low, ["elijah", "iphone", "ios"]) else "No",
        "supports_financial": "Yes" if has_financial else "No",
        "gaps": "Automated triage; source context and account/device ownership must be independently corroborated.",
        "followup": recommended_followup(services, low, tier),
        "direct_flags": {
            "elijah_iphone": contains_any(low, ["elijah", "iphone", "ios"]),
            "drive": has_drive_access,
            "gbp": has_gbp_access,
            "ip_device_location": has_ip or has_device or bool(row.get("Location", "").strip()),
        },
    }


def recommended_followup(services, low, tier):
    if tier == "Noise":
        return "No immediate follow-up unless this source file is tied to another higher-tier finding."
    if services & {"Access Log Activity", "Google Account", "Alerts"}:
        return "Correlate timestamp with Google security page, device list, IP geolocation, and any iPhone access records."
    if "Drive" in services:
        return "Review Drive metadata/activity export and original document metadata for exact view/download actor and timestamp."
    if "Google Business Profile" in services:
        return "Review Google Business Profile role/activity records for manager/owner changes or access events."
    if contains_any(low, FINANCIAL_TERMS):
        return "Correlate document filename/content with Drive activity, Gmail attachment logs, and testimony references."
    return "Review original extracted source around the snippet and correlate with adjacent Takeout services."


def triage_rows(hits):
    triaged = []
    for row in hits:
        c = score_and_classify(row)
        out = {
            "Rank": "",
            "RelevanceTier": c["tier"],
            "TimestampEastern": row.get("TimestampEastern") or row.get("TimestampRaw", ""),
            "Service": row.get("Service", ""),
            "EvidenceCategory": row.get("EvidenceCategory", ""),
            "Action": row.get("Action", ""),
            "DeviceInfo": row.get("DeviceInfo", ""),
            "IPAddress": row.get("IPAddress", ""),
            "Location": row.get("Location", ""),
            "FileOrDocumentName": row.get("FileOrDocumentName", ""),
            "MatchedTerms": row.get("MatchedTerms", ""),
            "SourceFile": row.get("SourceFile", ""),
            "SourceZip": row.get("SourceZip", ""),
            "EntryPath": row.get("EntryPath", ""),
            "Snippet": row.get("Snippet", ""),
            "WhyItMatters": c["why"],
            "SupportsUnauthorizedAccess": c["supports_unauthorized"],
            "SupportsElijahIphoneTheory": c["supports_elijah"],
            "SupportsFinancialDocumentAccess": c["supports_financial"],
            "GapsOrLimitations": c["gaps"],
            "RecommendedFollowUp": c["followup"],
            "_score": c["score"],
            "_flags": c["direct_flags"],
        }
        triaged.append(out)

    tier_order = {"Tier 1": 1, "Tier 2": 2, "Tier 3": 3, "Noise": 4}
    triaged.sort(key=lambda r: (tier_order[r["RelevanceTier"]], -r["_score"], r["TimestampEastern"], r["EntryPath"]))
    for i, row in enumerate(triaged, 1):
        row["Rank"] = i
    return triaged


def coverage_summary(inventory, extracted, hits, triaged):
    inv_counts = defaultdict(int)
    ext_counts = defaultdict(int)
    hit_counts = defaultdict(int)
    direct_counts = defaultdict(int)

    def add_counts(target, service_text):
        low = norm(service_text)
        for service in EXPECTED_SERVICES:
            probe = "Photos" if service == "Google Photos metadata" else service.replace(" Service", "")
            if probe.lower() in low:
                target[service] += 1

    for row in inventory:
        add_counts(inv_counts, row.get("PriorityService", "") + " " + row.get("EntryPath", ""))
    for row in extracted:
        add_counts(ext_counts, row.get("PriorityService", "") + " " + row.get("EntryPath", ""))
    for row in hits:
        add_counts(hit_counts, row.get("Service", "") + " " + row.get("EntryPath", ""))
    for row in triaged:
        if row["RelevanceTier"] == "Tier 1":
            add_counts(direct_counts, row.get("Service", "") + " " + row.get("EntryPath", ""))

    rows = []
    for service in EXPECTED_SERVICES:
        present = inv_counts[service] > 0
        if not present:
            notes = "Not yet searched because not present in the downloaded ZIP parts."
        elif hit_counts[service] == 0:
            notes = "Present in inventory/extraction, but no strict evidence hit was identified in first-pass hits."
        elif direct_counts[service] == 0:
            notes = "Present with evidence hits, but no Tier 1 direct-access hit after strict triage."
        else:
            notes = "Present with Tier 1 direct-access findings."
        rows.append(
            {
                "Service": service,
                "PresentInDownloadedZips": "Yes" if present else "No",
                "NumberOfFiles": inv_counts[service],
                "ExtractedFiles": ext_counts[service],
                "EvidenceHits": hit_counts[service],
                "DirectAccessHits": direct_counts[service],
                "Notes": notes,
            }
        )
    return rows


def md_table(rows, fields, limit=12):
    if not rows:
        return "None identified.\n"
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join(["---"] * len(fields)) + " |"]
    for row in rows[:limit]:
        vals = []
        for f in fields:
            val = str(row.get(f, "")).replace("|", "/").replace("\n", " ")
            if len(val) > 180:
                val = val[:177] + "..."
            vals.append(val)
        lines.append("| " + " | ".join(vals) + " |")
    return "\n".join(lines) + "\n"


def write_missing_md(scanned_zips, coverage):
    present = {r["Service"]: r for r in coverage}
    missing = [r for r in coverage if r["PresentInDownloadedZips"] == "No"]
    lines = [
        "# Missing Expected Evidence",
        "",
        "This note distinguishes absence from the downloaded ZIP parts from absence in the full Google Takeout. Only the ZIP files listed below were scanned; the case request states the full Takeout has 142 parts.",
        "",
        "## ZIP files scanned",
        *[f"- {Path(z).name}" for z in scanned_zips],
        "",
        "## Expected services",
    ]
    for service in EXPECTED_SERVICES:
        r = present[service]
        lines.append(f"- {service}: {r['PresentInDownloadedZips']} present; inventory files={r['NumberOfFiles']}; extracted files={r['ExtractedFiles']}; evidence hits={r['EvidenceHits']}; direct access hits={r['DirectAccessHits']}. {r['Notes']}")
    lines.extend(
        [
            "",
            "## Interpretation",
            "If a service is marked absent, it should be described as not yet searched because it is not present in the downloaded parts, not as proving no evidence exists.",
            "",
            "## Recommended next parts to inspect/download",
            "- Download or inspect all missing ZIP parts from the 142-part Takeout sequence, especially parts not currently present: everything other than the scanned `takeout-20260602T071913Z-11-001.zip`, `takeout-20260602T071913Z-13-001.zip`, and `takeout-20260602T071913Z-15-001.zip`.",
            "- Prioritize ZIP parts whose manifest paths contain `Access Log Activity`, `Google Account`, `Alerts`, `My Activity`, `Drive`, `Google Business Profile`, `Android Device Configuration`, `Chrome`, or `Photos` metadata.",
            "- If Google Takeout can be regenerated, request Account Activity, Security, My Activity, Drive, Chrome, Google Business Profile, and Google Photos metadata for April 19-26, 2024.",
        ]
    )
    if missing:
        lines.extend(["", "## Services absent from downloaded parts", *[f"- {r['Service']}" for r in missing]])
    MISSING_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_report(scanned_zips, coverage, triaged):
    tier1 = [r for r in triaged if r["RelevanceTier"] == "Tier 1"]
    tier2 = [r for r in triaged if r["RelevanceTier"] == "Tier 2"]
    tier3 = [r for r in triaged if r["RelevanceTier"] == "Tier 3"]
    noise = [r for r in triaged if r["RelevanceTier"] == "Noise"]
    elijah = [r for r in triaged if r["SupportsElijahIphoneTheory"] == "Yes" and r["RelevanceTier"] != "Noise"]
    drive_gbp = [r for r in triaged if ("Drive" in r["Service"] or "Google Business Profile" in r["Service"] or "Drive" in r["EntryPath"] or "Google Business Profile" in r["EntryPath"]) and r["RelevanceTier"] != "Noise"]
    financial = [r for r in triaged if r["SupportsFinancialDocumentAccess"] == "Yes" and r["RelevanceTier"] != "Noise"]
    cov = {r["Service"]: r for r in coverage}

    lines = [
        "# April 2024 Strict Forensic Triage Report",
        "",
        "## Executive summary",
        f"This second-pass triage reviewed {len(triaged)} first-pass evidence hits and narrowed them into {len(tier1)} Tier 1 direct-access findings, {len(tier2)} Tier 2 circumstantial findings, {len(tier3)} Tier 3 financial/business-context findings, and {len(noise)} excluded noise rows.",
        "Only 3 ZIP files were scanned, not the entire 142-part Google Takeout. Conclusions therefore apply only to the downloaded ZIP parts listed below.",
        "",
        "## ZIP files scanned",
        *[f"- {Path(z).name}" for z in scanned_zips],
        "",
        "## Service presence in downloaded ZIPs",
        f"- Access Log Activity present: {cov['Access Log Activity']['PresentInDownloadedZips']} ({cov['Access Log Activity']['NumberOfFiles']} files).",
        f"- My Activity present: {cov['My Activity']['PresentInDownloadedZips']} ({cov['My Activity']['NumberOfFiles']} files).",
        f"- Google Account/security/device files present: Google Account {cov['Google Account']['PresentInDownloadedZips']} ({cov['Google Account']['NumberOfFiles']} files); Alerts {cov['Alerts']['PresentInDownloadedZips']} ({cov['Alerts']['NumberOfFiles']} files); Android Device Configuration Service {cov['Android Device Configuration Service']['PresentInDownloadedZips']} ({cov['Android Device Configuration Service']['NumberOfFiles']} files).",
        f"- Drive metadata/activity files present: {cov['Drive']['PresentInDownloadedZips']} ({cov['Drive']['NumberOfFiles']} files).",
        f"- Google Business Profile files present: {cov['Google Business Profile']['PresentInDownloadedZips']} ({cov['Google Business Profile']['NumberOfFiles']} files).",
        "",
        "## Top Tier 1 findings",
        md_table(tier1, ["Rank", "TimestampEastern", "Service", "EvidenceCategory", "Action", "DeviceInfo", "IPAddress", "EntryPath", "WhyItMatters"], 15),
        "## Top Tier 2 findings",
        md_table(tier2, ["Rank", "TimestampEastern", "Service", "EvidenceCategory", "MatchedTerms", "EntryPath", "WhyItMatters"], 20),
        "## Financial/business document context findings",
        md_table(tier3, ["Rank", "TimestampEastern", "Service", "FileOrDocumentName", "MatchedTerms", "EntryPath", "WhyItMatters"], 20),
        "## Elijah iPhone/iOS access theory",
        md_table(elijah, ["Rank", "TimestampEastern", "Service", "DeviceInfo", "MatchedTerms", "EntryPath", "GapsOrLimitations"], 20),
        "## Drive or Google Business Profile access",
        md_table(drive_gbp, ["Rank", "TimestampEastern", "Service", "EvidenceCategory", "Action", "EntryPath", "RecommendedFollowUp"], 20),
        "## EIN/IRS/bank/financial/Helo records",
        md_table(financial, ["Rank", "TimestampEastern", "Service", "FileOrDocumentName", "MatchedTerms", "EntryPath", "RecommendedFollowUp"], 20),
        "## Gaps and limitations",
        "- This triage used generated first-pass hits and extracted text/metadata only; it did not extract additional large files or original ZIP contents.",
        "- A Takeout artifact can show account activity or document context, but it may not identify who physically held or used a device.",
        "- Absence of a finding in these 3 ZIPs is not absence from the full 142-part Takeout.",
        "- Generic My Activity entries such as Discover card views were treated as noise unless tied to device, person, sensitive document, Drive, security, IP, or Google Business Profile evidence.",
        "",
        "## Specific next ZIP parts to download or inspect",
        "- Inspect/download the remaining parts of the stated 142-part Takeout sequence, excluding the three scanned here: `takeout-20260602T071913Z-11-001.zip`, `takeout-20260602T071913Z-13-001.zip`, and `takeout-20260602T071913Z-15-001.zip`.",
        "- Prioritize any remaining parts whose filenames/manifests contain `Access Log Activity`, `Google Account`, `Alerts`, `My Activity`, `Drive`, `Google Business Profile`, `Android Device Configuration`, `Chrome`, or Google Photos metadata.",
        "- If available, regenerate or separately export Google account security/device logs and My Activity for April 19-26, 2024.",
    ]
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    TRIAGE_DIR.mkdir(parents=True, exist_ok=True)
    inventory = read_csv(INVENTORY_CSV)
    extracted = read_csv(EXTRACTED_CSV)
    hits = read_csv(HITS_CSV)
    triaged = triage_rows(hits)

    tier1 = [r for r in triaged if r["RelevanceTier"] == "Tier 1"]
    tier2 = [r for r in triaged if r["RelevanceTier"] == "Tier 2"]
    tier3 = [r for r in triaged if r["RelevanceTier"] == "Tier 3"]
    noise = [r for r in triaged if r["RelevanceTier"] == "Noise"]

    write_csv(CRITICAL_CSV, triaged, TRIAGE_FIELDS)
    write_csv(TIER1_CSV, tier1, TRIAGE_FIELDS)
    write_csv(TIER2_CSV, tier2, TRIAGE_FIELDS)
    write_csv(TIER3_CSV, tier3, TRIAGE_FIELDS)
    write_csv(NOISE_CSV, noise, TRIAGE_FIELDS)

    coverage = coverage_summary(inventory, extracted, hits, triaged)
    write_csv(COVERAGE_CSV, coverage, ["Service", "PresentInDownloadedZips", "NumberOfFiles", "ExtractedFiles", "EvidenceHits", "DirectAccessHits", "Notes"])

    scanned_zips = sorted({r.get("ZipFile", "") for r in inventory if r.get("ZipFile")})
    write_missing_md(scanned_zips, coverage)
    write_report(scanned_zips, coverage, triaged)

    flags = [r.get("_flags", {}) for r in triaged if r["RelevanceTier"] != "Noise"]
    print(f"Total hits reviewed: {len(hits)}")
    print(f"Tier 1 count: {len(tier1)}")
    print(f"Tier 2 count: {len(tier2)}")
    print(f"Tier 3 count: {len(tier3)}")
    print(f"Noise count: {len(noise)}")
    print(f"Direct evidence of Elijah/iPhone access found: {'Yes' if any(f.get('elijah_iphone') and r['RelevanceTier'] == 'Tier 1' for f, r in zip([x.get('_flags', {}) for x in triaged], triaged)) else 'No'}")
    print(f"Any Elijah/iPhone evidence or circumstantial signal found: {'Yes' if any(f.get('elijah_iphone') for f in flags) else 'No'}")
    print(f"Drive view/download evidence found: {'Yes' if any(f.get('drive') for f in flags) else 'No'}")
    print(f"Google Business Profile access evidence found: {'Yes' if any(f.get('gbp') for f in flags) else 'No'}")
    print(f"IP/device/location data found: {'Yes' if any(f.get('ip_device_location') for f in flags) else 'No'}")
    print(f"Triage folder: {TRIAGE_DIR}")


if __name__ == "__main__":
    main()
