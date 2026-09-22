import csv
import datetime as dt
import os
import zipfile
from pathlib import Path


ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
DEST = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
OUT = DEST / "_forensic_outputs"
PARTS = [f"takeout-20260602T071913Z-7-{i:03d}.zip" for i in range(26, 49)]


def safe_dest(base: Path, member: str) -> Path:
    target = (base / member).resolve()
    base_resolved = base.resolve()
    if base_resolved not in target.parents and target != base_resolved:
        raise ValueError(f"Unsafe ZIP path: {member}")
    return target


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    summary = []
    errors = []
    source_map = []

    for name in PARTS:
        zip_path = ZIP_DIR / name
        if not zip_path.exists():
            summary.append({
                "Zip": str(zip_path),
                "ZipFilename": name,
                "Status": "Missing",
                "ZipSize": "",
                "UncompressedBytes": "",
                "FileEntries": 0,
                "ExtractedNewFiles": 0,
                "SkippedExisting": 0,
                "Errors": 0,
            })
            continue

        extracted = 0
        skipped = 0
        err_count = 0
        uncompressed = 0
        file_entries = 0

        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                file_entries += 1
                uncompressed += info.file_size
                try:
                    target = safe_dest(DEST, info.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    already_same = target.exists() and target.stat().st_size == info.file_size
                    if not already_same:
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
                        "SourceZipFilename": name,
                        "EntryPath": info.filename,
                        "ExtractedPath": str(target),
                        "EntrySize": info.file_size,
                        "EntryModified": dt.datetime(*info.date_time).isoformat(sep=" ", timespec="seconds"),
                        "ExtractedStatus": "SkippedExisting" if already_same else "Extracted",
                    })
                except Exception as exc:
                    err_count += 1
                    errors.append({
                        "Zip": str(zip_path),
                        "ZipFilename": name,
                        "Entry": info.filename,
                        "Error": str(exc),
                    })

        summary.append({
            "Zip": str(zip_path),
            "ZipFilename": name,
            "Status": "Processed",
            "ZipSize": zip_path.stat().st_size,
            "UncompressedBytes": uncompressed,
            "FileEntries": file_entries,
            "ExtractedNewFiles": extracted,
            "SkippedExisting": skipped,
            "Errors": err_count,
        })

    with (OUT / "parts_026_048_extraction_summary.csv").open("w", encoding="utf-8-sig", newline="") as f:
        headers = [
            "Zip", "ZipFilename", "Status", "ZipSize", "UncompressedBytes",
            "FileEntries", "ExtractedNewFiles", "SkippedExisting", "Errors",
        ]
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(summary)

    with (OUT / "parts_026_048_extraction_errors.csv").open("w", encoding="utf-8-sig", newline="") as f:
        headers = ["Zip", "ZipFilename", "Entry", "Error"]
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(errors)

    with (OUT / "parts_026_048_source_zip_map.csv").open("w", encoding="utf-8-sig", newline="") as f:
        headers = [
            "SourceZip", "SourceZipFilename", "EntryPath", "ExtractedPath",
            "EntrySize", "EntryModified", "ExtractedStatus",
        ]
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(source_map)

    print("Processed Takeout parts 026-048")
    print(f"Extracted new files: {sum(int(r['ExtractedNewFiles']) for r in summary)}")
    print(f"Skipped existing files: {sum(int(r['SkippedExisting']) for r in summary)}")
    print(f"Errors: {len(errors)}")
    print(f"Source map: {OUT / 'parts_026_048_source_zip_map.csv'}")


if __name__ == "__main__":
    main()
