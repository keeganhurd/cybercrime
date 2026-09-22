import csv
import zipfile
from pathlib import Path


ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
EXTRACTED = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
TAKEOUT_ROOT = EXTRACTED / "Takeout"
OUT = EXTRACTED / "_forensic_outputs"

IMPORTANT_SOURCE_FILES = {
    "Takeout/My Activity/Gmail/MyActivity.html",
    "Takeout/My Activity/Search/MyActivity.html",
    "Takeout/My Activity/Drive/MyActivity.html",
    "Takeout/Access Log Activity/Activities - A list of Google services accessed by.csv",
    "Takeout/Access Log Activity/Devices - A list of devices (i.e. Nest, Pixel, iPh.csv",
    "Takeout/Google Account/keeganhurd.ChangeHistory.html",
    "Takeout/Google Account/keeganhurd.SubscriberInfo.html",
    "Takeout/Chrome/Device Information.json",
}


def add_sources_from_csv(path, col):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            src = row.get(col) or row.get("Source File") or row.get("SourceFile")
            if not src:
                continue
            try:
                p = Path(src)
                if p.is_absolute():
                    rel = p.relative_to(EXTRACTED).as_posix()
                else:
                    rel = src.replace("\\", "/")
                if rel.startswith("Takeout/"):
                    IMPORTANT_SOURCE_FILES.add(rel)
            except Exception:
                pass


def build_zip_index():
    mapping = {}
    zip_sizes = {}
    zip_entries = {}
    for zp in sorted(ZIP_DIR.glob("*.zip")):
        zip_sizes[zp.name] = zp.stat().st_size
        zip_entries[zp.name] = 0
        try:
            with zipfile.ZipFile(zp) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename.replace("\\", "/")
                    mapping.setdefault(name, []).append(zp.name)
                    zip_entries[zp.name] += 1
        except Exception:
            pass
    return mapping, zip_sizes, zip_entries


def folder_size(path):
    total = 0
    if path.exists():
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except Exception:
                    pass
    return total


def main():
    add_sources_from_csv(OUT / "timeline.csv", "Source File")
    add_sources_from_csv(OUT / "Drive_Activity_Timeline.csv", "SourceFile")
    add_sources_from_csv(OUT / "Drive_Keyword_Hits.csv", "SourceFile")

    mapping, zip_sizes, zip_entries = build_zip_index()
    keep = set()
    source_rows = []
    for src in sorted(IMPORTANT_SOURCE_FILES):
        zips = mapping.get(src, [])
        for z in zips:
            keep.add(z)
        source_rows.append({
            "SourceArtifact": src,
            "ContainingZips": "; ".join(zips) if zips else "NOT FOUND IN ZIP INDEX",
        })

    all_zips = set(zip_sizes)
    delete_candidates = sorted(all_zips - keep)
    keep_rows = []
    for z in sorted(keep):
        keep_rows.append({"Zip": z, "SizeGB": round(zip_sizes[z] / 1024**3, 3), "Entries": zip_entries.get(z, 0), "Reason": "Contains source artifact used by reports/audits"})
    delete_rows = []
    for z in delete_candidates:
        delete_rows.append({"Zip": z, "SizeGB": round(zip_sizes[z] / 1024**3, 3), "Entries": zip_entries.get(z, 0), "Reason": "No currently identified report source artifact mapped to this ZIP"})

    with (OUT / "Takeout_Cleanup_Source_To_Zip_Map.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["SourceArtifact", "ContainingZips"])
        w.writeheader()
        w.writerows(source_rows)
    with (OUT / "Takeout_Cleanup_Keep_Zips.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Zip", "SizeGB", "Entries", "Reason"])
        w.writeheader()
        w.writerows(keep_rows)
    with (OUT / "Takeout_Cleanup_Delete_Candidate_Zips.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Zip", "SizeGB", "Entries", "Reason"])
        w.writeheader()
        w.writerows(delete_rows)

    mbox = ZIP_DIR / "All mail Including Spam and Trash-002.mbox"
    total_delete = sum(zip_sizes[z] for z in delete_candidates)
    total_keep = sum(zip_sizes[z] for z in keep)
    print("Cleanup plan created")
    print(f"Keep ZIPs: {len(keep)} / {round(total_keep / 1024**3, 2)} GB")
    print(f"Delete candidate ZIPs: {len(delete_candidates)} / {round(total_delete / 1024**3, 2)} GB")
    print(f"Takeout Zips folder size: {round(folder_size(ZIP_DIR) / 1024**3, 2)} GB")
    print(f"Takeout Extracted folder size: {round(folder_size(EXTRACTED) / 1024**3, 2)} GB")
    print(f"Forensic outputs size: {round(folder_size(OUT) / 1024**3, 2)} GB")
    if mbox.exists():
        print(f"Large MBOX in ZIP folder: {round(mbox.stat().st_size / 1024**3, 2)} GB")
    print(f"Keep list: {OUT / 'Takeout_Cleanup_Keep_Zips.csv'}")
    print(f"Delete candidate list: {OUT / 'Takeout_Cleanup_Delete_Candidate_Zips.csv'}")


if __name__ == "__main__":
    main()
