import csv
import datetime as dt
import os
import zipfile
from pathlib import Path


ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
DEST = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
OUT = DEST / "_forensic_outputs"

KEEP_EXTS = {
    ".csv", ".json", ".html", ".htm", ".txt", ".xml", ".log", ".md",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".sqlite", ".sqlite3", ".db",
}
MEDIA_EXTS = {".mp4", ".mov", ".avi", ".mkv", ".vob", ".mpg", ".mpeg", ".mp3", ".m4a", ".jpg", ".jpeg", ".png", ".gif", ".heic"}
INTEREST_TERMS = [
    "helo", "ein", "irs", "navy", "bank", "statement", "merchant", "stripe",
    "authorize", "payanywhere", "docusign", "business", "gmail", "drive",
    "hurd family legal", "tom hurd legal", "expert it", "victor it", "kula yoga",
    "google business", "florida crystal", "file_5531", "payment services",
]
MAX_MEDIA_BYTES = 25 * 1024 * 1024


def safe_dest(base: Path, member: str) -> Path:
    target = (base / member).resolve()
    base_resolved = base.resolve()
    if base_resolved not in target.parents and target != base_resolved:
        raise ValueError(f"Unsafe ZIP path: {member}")
    return target


def decision(info):
    entry = info.filename.replace("\\", "/")
    low = entry.lower()
    ext = Path(entry).suffix.lower()
    if ext in KEEP_EXTS:
        return "ExtractEvidenceType"
    if any(term in low for term in INTEREST_TERMS):
        if ext in MEDIA_EXTS and info.file_size > MAX_MEDIA_BYTES:
            return "SkipLargeMediaEvenIfNamed"
        return "ExtractNamedRelevant"
    if ext in MEDIA_EXTS:
        return "SkipMedia"
    if info.file_size > MAX_MEDIA_BYTES:
        return "SkipLargeOther"
    return "SkipNotRelevant"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    summary = []
    errors = []
    source_map = []
    zip_paths = sorted(ZIP_DIR.glob("*.zip"))

    for zip_path in zip_paths:
        extracted = skipped_existing = skipped_policy = err_count = entries = 0
        uncompressed = selected_bytes = 0
        try:
            zf = zipfile.ZipFile(zip_path)
        except Exception as exc:
            errors.append({"Zip": str(zip_path), "ZipFilename": zip_path.name, "Entry": "", "Error": str(exc)})
            summary.append({"Zip": str(zip_path), "ZipFilename": zip_path.name, "Status": "OpenError", "ZipSize": zip_path.stat().st_size if zip_path.exists() else "", "UncompressedBytes": "", "SelectedBytes": "", "FileEntries": 0, "ExtractedNewFiles": 0, "SkippedExisting": 0, "SkippedByPolicy": 0, "Errors": 1})
            continue

        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                entries += 1
                uncompressed += info.file_size
                dec = decision(info)
                try:
                    target = safe_dest(DEST, info.filename)
                    same = target.exists() and target.stat().st_size == info.file_size
                    if dec.startswith("Skip"):
                        skipped_policy += 1
                        status = dec
                    elif same:
                        skipped_existing += 1
                        status = "SkippedExisting"
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(info) as src, target.open("wb") as dst:
                            while True:
                                chunk = src.read(1024 * 1024)
                                if not chunk:
                                    break
                                dst.write(chunk)
                        try:
                            mtime = dt.datetime(*info.date_time).timestamp()
                            os.utime(target, (mtime, mtime))
                        except Exception:
                            pass
                        extracted += 1
                        selected_bytes += info.file_size
                        status = dec
                    source_map.append({
                        "SourceZip": str(zip_path),
                        "SourceZipFilename": zip_path.name,
                        "EntryPath": info.filename,
                        "ExtractedPath": str(target),
                        "EntrySize": info.file_size,
                        "EntryModified": dt.datetime(*info.date_time).isoformat(sep=" ", timespec="seconds"),
                        "ExtractedStatus": status,
                    })
                except Exception as exc:
                    err_count += 1
                    errors.append({"Zip": str(zip_path), "ZipFilename": zip_path.name, "Entry": info.filename, "Error": str(exc), "Decision": dec})

        summary.append({
            "Zip": str(zip_path), "ZipFilename": zip_path.name, "Status": "ProcessedSelective",
            "ZipSize": zip_path.stat().st_size, "UncompressedBytes": uncompressed, "SelectedBytes": selected_bytes,
            "FileEntries": entries, "ExtractedNewFiles": extracted, "SkippedExisting": skipped_existing,
            "SkippedByPolicy": skipped_policy, "Errors": err_count,
        })

    summary_path = OUT / f"selective_extraction_summary_{stamp}.csv"
    errors_path = OUT / f"selective_extraction_errors_{stamp}.csv"
    map_path = OUT / f"selective_source_map_{stamp}.csv"
    current_map = OUT / "current_takeout_zips_source_map.csv"
    current_summary = OUT / "current_takeout_zips_extraction_summary.csv"
    current_errors = OUT / "current_takeout_zips_extraction_errors.csv"

    headers = ["Zip", "ZipFilename", "Status", "ZipSize", "UncompressedBytes", "SelectedBytes", "FileEntries", "ExtractedNewFiles", "SkippedExisting", "SkippedByPolicy", "Errors"]
    for path in (summary_path, current_summary):
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(summary)

    err_headers = ["Zip", "ZipFilename", "Entry", "Error", "Decision"]
    for path in (errors_path, current_errors):
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=err_headers)
            writer.writeheader()
            writer.writerows(errors)

    map_headers = ["SourceZip", "SourceZipFilename", "EntryPath", "ExtractedPath", "EntrySize", "EntryModified", "ExtractedStatus"]
    for path in (map_path, current_map):
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=map_headers)
            writer.writeheader()
            writer.writerows(source_map)

    print(f"ZIPs processed selective: {len(zip_paths)}")
    print(f"Extracted new files: {sum(int(r['ExtractedNewFiles']) for r in summary)}")
    print(f"Skipped existing: {sum(int(r['SkippedExisting']) for r in summary)}")
    print(f"Skipped by policy: {sum(int(r['SkippedByPolicy']) for r in summary)}")
    print(f"Errors: {len(errors)}")
    print(f"Summary: {summary_path}")
    print(f"Source map: {map_path}")


if __name__ == "__main__":
    main()
