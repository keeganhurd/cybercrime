import csv
import zipfile
from pathlib import Path


ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
DEST = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
OUT = DEST / "_forensic_outputs"
PARTS = [f"takeout-20260602T071913Z-7-{i:03d}.zip" for i in range(18, 26)]


def safe_dest(base, member):
    target = (base / member).resolve()
    base_resolved = base.resolve()
    if base_resolved not in target.parents and target != base_resolved:
        raise ValueError(f"Unsafe ZIP path: {member}")
    return target


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    summary = []
    errors = []
    for name in PARTS:
        zip_path = ZIP_DIR / name
        if not zip_path.exists():
            summary.append({"Zip": str(zip_path), "Status": "Missing", "ExtractedNewFiles": 0, "SkippedExisting": 0, "Errors": 0})
            continue
        extracted = 0
        skipped = 0
        err_count = 0
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    target = safe_dest(DEST, info.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists() and target.stat().st_size == info.file_size:
                        skipped += 1
                        continue
                    with zf.open(info) as src, target.open("wb") as dst:
                        while True:
                            chunk = src.read(1024 * 1024)
                            if not chunk:
                                break
                            dst.write(chunk)
                    extracted += 1
                except Exception as exc:
                    err_count += 1
                    errors.append({"Zip": str(zip_path), "Entry": info.filename, "Error": str(exc)})
        summary.append({"Zip": str(zip_path), "Status": "Processed", "ExtractedNewFiles": extracted, "SkippedExisting": skipped, "Errors": err_count})

    with (OUT / "new_parts_extraction_summary.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Zip", "Status", "ExtractedNewFiles", "SkippedExisting", "Errors"])
        w.writeheader()
        w.writerows(summary)
    with (OUT / "new_parts_extraction_errors.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Zip", "Entry", "Error"])
        w.writeheader()
        w.writerows(errors)
    print("Processed new Takeout parts")
    print(f"Extracted new files: {sum(int(r['ExtractedNewFiles']) for r in summary)}")
    print(f"Skipped existing files: {sum(int(r['SkippedExisting']) for r in summary)}")
    print(f"Errors: {len(errors)}")
    print(f"Summary: {OUT / 'new_parts_extraction_summary.csv'}")


if __name__ == "__main__":
    main()
