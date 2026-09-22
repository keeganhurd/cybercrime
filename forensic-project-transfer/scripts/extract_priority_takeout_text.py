import csv
import hashlib
import shutil
import sys
import zipfile
from pathlib import Path, PurePosixPath

ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
OUT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024")
EXTRACT_DIR = OUT_DIR / "Extracted Priority Text"
OUT_CSV = OUT_DIR / "extracted_priority_files.csv"

PRIORITY_TERMS = [
    "Access Log Activity",
    "My Activity",
    "Alerts",
    "Google Account",
    "Drive",
    "Google Business Profile",
    "Android Device Configuration",
    "Android Device Configuration Service",
    "Chrome",
    "Photos",
]
TEXT_EXTS = {".json", ".html", ".htm", ".csv", ".txt", ".xml", ".ics"}
SMALL_MBOX_LIMIT = 25 * 1024 * 1024
SINGLE_LIMIT = 250 * 1024 * 1024
TOTAL_LIMIT = 500 * 1024 * 1024


def priority_service(path):
    low = path.lower()
    found = [term for term in PRIORITY_TERMS if term.lower() in low]
    return "; ".join(dict.fromkeys(found))


def safe_output_path(zip_path, entry):
    parts = [p for p in PurePosixPath(entry).parts if p not in ("", ".", "..")]
    return EXTRACT_DIR / zip_path.stem / Path(*parts)


def extended_path(path):
    resolved = str(path.resolve())
    if resolved.startswith("\\\\?\\"):
        return resolved
    return "\\\\?\\" + resolved


def eligible(info):
    service = priority_service(info.filename)
    if not service or info.is_dir():
        return False, service
    suffix = Path(info.filename).suffix.lower()
    if suffix in TEXT_EXTS:
        return True, service
    if suffix == ".mbox" and info.file_size <= SMALL_MBOX_LIMIT:
        allowed = ("alerts" in info.filename.lower()) or ("google account" in info.filename.lower())
        return allowed, service
    return False, service


def sha256_file(path):
    h = hashlib.sha256()
    with open(extended_path(path), "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    candidates = []
    for zip_path in sorted(ZIP_DIR.glob("*.zip")):
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                ok, service = eligible(info)
                if ok:
                    candidates.append((zip_path, info.filename, info.file_size, service))

    total_size = sum(size for _, _, size, _ in candidates)
    too_large = [(z, e, s) for z, e, s, _ in candidates if s > SINGLE_LIMIT]
    print(f"Eligible text/metadata files: {len(candidates)}")
    print(f"Planned uncompressed extraction bytes: {total_size}")
    if too_large:
        print("Extraction blocked: at least one candidate is larger than 250 MB.")
        for z, e, s in too_large[:20]:
            print(f"{s}\t{z.name}\t{e}")
        sys.exit(2)
    if total_size > TOTAL_LIMIT:
        print("Extraction blocked: total candidate size is larger than 500 MB.")
        sys.exit(3)

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for zip_path, entry, size, service in candidates:
        out_path = safe_output_path(zip_path, entry)
        Path(extended_path(out_path.parent)).mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path) as zf, zf.open(entry) as src, open(extended_path(out_path), "wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
        rows.append(
            {
                "SourceZip": str(zip_path),
                "EntryPath": entry,
                "OutputPath": str(out_path),
                "Size": size,
                "SHA256": sha256_file(out_path),
                "PriorityService": service,
            }
        )

    with OUT_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["SourceZip", "EntryPath", "OutputPath", "Size", "SHA256", "PriorityService"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Extracted files: {len(rows)}")
    print(f"Extracted CSV: {OUT_CSV}")
    print(f"Extraction folder: {EXTRACT_DIR}")


if __name__ == "__main__":
    main()
