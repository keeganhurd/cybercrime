import csv
import datetime as dt
import os
import zipfile
from pathlib import Path


ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
DEST = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
OUT = DEST / "_forensic_outputs"


def safe_dest(base: Path, member: str) -> Path:
    target = (base / member).resolve()
    base_resolved = base.resolve()
    if base_resolved not in target.parents and target != base_resolved:
        raise ValueError(f"Unsafe ZIP path: {member}")
    return target


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    zip_paths = sorted(ZIP_DIR.glob("*.zip"))
    summary = []
    errors = []
    source_map = []

    for zip_path in zip_paths:
        extracted = 0
        skipped = 0
        err_count = 0
        entries = 0
        uncompressed = 0
        try:
            zf = zipfile.ZipFile(zip_path)
        except Exception as exc:
            errors.append({"Zip": str(zip_path), "ZipFilename": zip_path.name, "Entry": "", "Error": str(exc)})
            summary.append({
                "Zip": str(zip_path), "ZipFilename": zip_path.name, "Status": "OpenError",
                "ZipSize": zip_path.stat().st_size if zip_path.exists() else "",
                "UncompressedBytes": "", "FileEntries": 0, "ExtractedNewFiles": 0,
                "SkippedExisting": 0, "Errors": 1,
            })
            continue

        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                entries += 1
                uncompressed += info.file_size
                try:
                    target = safe_dest(DEST, info.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    same = target.exists() and target.stat().st_size == info.file_size
                    if not same:
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
                    else:
                        skipped += 1
                    source_map.append({
                        "SourceZip": str(zip_path),
                        "SourceZipFilename": zip_path.name,
                        "EntryPath": info.filename,
                        "ExtractedPath": str(target),
                        "EntrySize": info.file_size,
                        "EntryModified": dt.datetime(*info.date_time).isoformat(sep=" ", timespec="seconds"),
                        "ExtractedStatus": "SkippedExisting" if same else "Extracted",
                    })
                except Exception as exc:
                    err_count += 1
                    errors.append({"Zip": str(zip_path), "ZipFilename": zip_path.name, "Entry": info.filename, "Error": str(exc)})

        summary.append({
            "Zip": str(zip_path), "ZipFilename": zip_path.name, "Status": "Processed",
            "ZipSize": zip_path.stat().st_size, "UncompressedBytes": uncompressed,
            "FileEntries": entries, "ExtractedNewFiles": extracted, "SkippedExisting": skipped,
            "Errors": err_count,
        })

    headers = ["Zip", "ZipFilename", "Status", "ZipSize", "UncompressedBytes", "FileEntries", "ExtractedNewFiles", "SkippedExisting", "Errors"]
    with (OUT / "current_takeout_zips_extraction_summary.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(summary)

    err_headers = ["Zip", "ZipFilename", "Entry", "Error"]
    with (OUT / "current_takeout_zips_extraction_errors.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=err_headers)
        writer.writeheader()
        writer.writerows(errors)

    map_headers = ["SourceZip", "SourceZipFilename", "EntryPath", "ExtractedPath", "EntrySize", "EntryModified", "ExtractedStatus"]
    with (OUT / "current_takeout_zips_source_map.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=map_headers)
        writer.writeheader()
        writer.writerows(source_map)

    print(f"ZIPs processed: {len(zip_paths)}")
    print(f"Extracted new files: {sum(int(r['ExtractedNewFiles']) for r in summary if r['ExtractedNewFiles'] != '')}")
    print(f"Skipped existing files: {sum(int(r['SkippedExisting']) for r in summary if r['SkippedExisting'] != '')}")
    print(f"Errors: {len(errors)}")
    print(f"Summary: {OUT / 'current_takeout_zips_extraction_summary.csv'}")
    print(f"Source map: {OUT / 'current_takeout_zips_source_map.csv'}")


if __name__ == "__main__":
    main()
