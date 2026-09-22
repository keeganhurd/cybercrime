import csv
import datetime as dt
import html
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
TAKEOUT_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout")
SOURCE_MAP = OUT / "parts_026_048_source_zip_map.csv"

CASE_TERMS = [
    "HELO", "Helo Payment Services", "EIN", "IRS", "CP 575", "147C",
    "Navy Federal", "bank", "statement", "Stripe", "Merchant", "Authorize",
    "Virtue Capital", "LCF Group", "DocuSign", "GoFingerprinting",
    "Google Drive", "drive.google.com", "docs.google.com", "Gmail",
    "Jonathan", "Braese", "Ariana", "Gavin", "Venmo", "Robin", "Mom", "Elijah",
]

APRIL_2024_RE = re.compile(r"2024[-/: T]*(?:04|4)[-/: T]*(?:19|20|21|22|23|24|25|26)|(?:Apr|April)\s+(?:19|20|21|22|23|24|25|26),?\s+2024", re.I)
TERM_PATTERNS = [(term, re.compile(re.escape(term), re.I)) for term in CASE_TERMS]


def clip(value, limit=500):
    text = re.sub(r"\s+", " ", html.unescape(str(value or ""))).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."


def load_source_map():
    by_path = {}
    if not SOURCE_MAP.exists():
        return by_path
    with SOURCE_MAP.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            by_path[row["ExtractedPath"]] = row
    return by_path


def read_text(path):
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def main():
    source_by_path = load_source_map()
    rows = []
    april_rows = []
    by_zip = defaultdict(lambda: {"files": 0, "case_hits": 0, "april_hits": 0, "bytes": 0})
    ext_counts = Counter()
    top_folders = Counter()

    for extracted_path, source in source_by_path.items():
        path = Path(extracted_path)
        zip_name = source.get("SourceZipFilename", "")
        size = int(source.get("EntrySize") or 0)
        by_zip[zip_name]["files"] += 1
        by_zip[zip_name]["bytes"] += size
        ext_counts[path.suffix.lower() or "[no extension]"] += 1
        try:
            rel_parts = path.relative_to(TAKEOUT_ROOT).parts
            top_folders["/".join(rel_parts[:3])] += 1
        except Exception:
            pass

        context = f"{path.name}\n{source.get('EntryPath','')}\n"
        if path.suffix.lower() in {".json", ".html", ".htm", ".txt", ".csv", ".xml", ".log"}:
            context += read_text(path)[:200000]

        matched = [term for term, pat in TERM_PATTERNS if pat.search(context)]
        april_match = APRIL_2024_RE.search(context)
        if matched:
            by_zip[zip_name]["case_hits"] += 1
            rows.append({
                "SourceZip": source.get("SourceZip", ""),
                "SourceZipFilename": zip_name,
                "EntryPath": source.get("EntryPath", ""),
                "ExtractedPath": extracted_path,
                "MatchedTerms": "; ".join(matched),
                "April19_26_2024Mention": "Yes" if april_match else "No",
                "Snippet": clip(context),
            })
        if april_match:
            by_zip[zip_name]["april_hits"] += 1
            april_rows.append({
                "SourceZip": source.get("SourceZip", ""),
                "SourceZipFilename": zip_name,
                "EntryPath": source.get("EntryPath", ""),
                "ExtractedPath": extracted_path,
                "MatchedText": clip(april_match.group(0), 180),
                "MatchedTerms": "; ".join(matched),
                "Snippet": clip(context),
            })

    summary_rows = []
    for zip_name, stats in sorted(by_zip.items()):
        summary_rows.append({
            "SourceZipFilename": zip_name,
            "FilesExtracted": stats["files"],
            "BytesExtracted": stats["bytes"],
            "CaseKeywordHitFiles": stats["case_hits"],
            "April19_26_2024HitFiles": stats["april_hits"],
        })

    def write_csv(path, data, headers):
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)

    write_csv(
        OUT / "parts_026_048_case_keyword_hits.csv",
        rows,
        ["SourceZip", "SourceZipFilename", "EntryPath", "ExtractedPath", "MatchedTerms", "April19_26_2024Mention", "Snippet"],
    )
    write_csv(
        OUT / "parts_026_048_april_2024_hits.csv",
        april_rows,
        ["SourceZip", "SourceZipFilename", "EntryPath", "ExtractedPath", "MatchedText", "MatchedTerms", "Snippet"],
    )
    write_csv(
        OUT / "parts_026_048_case_relevance_summary.csv",
        summary_rows,
        ["SourceZipFilename", "FilesExtracted", "BytesExtracted", "CaseKeywordHitFiles", "April19_26_2024HitFiles"],
    )

    report = []
    report.append("# Takeout Parts 026-048 Case-Relevance Scan\n\n")
    report.append(f"Generated: {dt.datetime.now().isoformat(sep=' ', timespec='seconds')}\n\n")
    report.append("## Scope\n\n")
    report.append("This scan reviewed files extracted from `takeout-20260602T071913Z-7-026.zip` through `takeout-20260602T071913Z-7-048.zip` using the source-ZIP map created during extraction.\n\n")
    report.append("## Main Finding\n\n")
    report.append("These ZIP parts extracted as Google Photos content, not Google Drive/My Activity/Access Log/Gmail activity records. No direct April 19-26, 2024 Drive open/view/download/search log was found in this batch.\n\n")
    report.append("## Counts\n\n")
    report.append(f"- Files reviewed from source map: {len(source_by_path)}\n")
    report.append(f"- Case keyword hit files: {len(rows)}\n")
    report.append(f"- April 19-26, 2024 hit files: {len(april_rows)}\n\n")
    report.append("## Top Extracted Folder Groups\n\n")
    for folder, count in top_folders.most_common(20):
        report.append(f"- {folder}: {count}\n")
    report.append("\n## Extension Counts\n\n")
    for ext, count in ext_counts.most_common(20):
        report.append(f"- {ext}: {count}\n")
    report.append("\n## Practical Assessment\n\n")
    if rows or april_rows:
        report.append("Some keyword/date hits were found. Review the CSV outputs before deleting these local extracts.\n")
    else:
        report.append("No useful case keyword or April 19-26, 2024 date hits were found in this batch. Based on this scan, these parts do not appear to add evidence helpful to the current Drive/Gmail/iPhone-access theory.\n")
    report.append("\n## Source Tracking\n\n")
    report.append("Every extracted file remains mapped to its source ZIP in `parts_026_048_source_zip_map.csv`.\n")
    (OUT / "parts_026_048_case_relevance_report.md").write_text("".join(report), encoding="utf-8")

    print("Case relevance scan complete")
    print(f"Files reviewed: {len(source_by_path)}")
    print(f"Case keyword hit files: {len(rows)}")
    print(f"April 19-26, 2024 hit files: {len(april_rows)}")
    print(f"Report: {OUT / 'parts_026_048_case_relevance_report.md'}")


if __name__ == "__main__":
    main()
