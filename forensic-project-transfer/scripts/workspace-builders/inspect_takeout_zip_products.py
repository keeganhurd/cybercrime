import csv
import zipfile
from collections import Counter, defaultdict
from pathlib import Path


ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")


def group_name(filename):
    # takeout-20260602T071913Z-7-086.zip -> 7
    stem = Path(filename).stem
    parts = stem.split("-")
    if len(parts) >= 4 and parts[-1].isdigit() and parts[-2].isdigit():
        return parts[-2]
    return ""


def top_product(entry):
    bits = entry.replace("\\", "/").split("/")
    if len(bits) >= 3 and bits[0] == "Takeout":
        return "/".join(bits[:3])
    if len(bits) >= 2:
        return "/".join(bits[:2])
    return entry


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    group_counts = defaultdict(Counter)
    for zip_path in sorted(ZIP_DIR.glob("*.zip")):
        group = group_name(zip_path.name)
        try:
            with zipfile.ZipFile(zip_path) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                counts = Counter(top_product(i.filename) for i in infos)
                total_uncompressed = sum(i.file_size for i in infos)
                for product, count in counts.most_common():
                    group_counts[group][product] += count
                    rows.append({
                        "ZipFilename": zip_path.name,
                        "GroupNumber": group,
                        "ProductOrTopFolder": product,
                        "FileCount": count,
                        "ZipSize": zip_path.stat().st_size,
                        "UncompressedBytesInZip": total_uncompressed,
                    })
        except Exception as exc:
            rows.append({
                "ZipFilename": zip_path.name,
                "GroupNumber": group,
                "ProductOrTopFolder": f"ERROR: {exc}",
                "FileCount": "",
                "ZipSize": zip_path.stat().st_size if zip_path.exists() else "",
                "UncompressedBytesInZip": "",
            })

    with (OUT / "takeout_zip_product_inspection.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ZipFilename", "GroupNumber", "ProductOrTopFolder", "FileCount", "ZipSize", "UncompressedBytesInZip"])
        writer.writeheader()
        writer.writerows(rows)

    with (OUT / "takeout_zip_group_product_summary.csv").open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["GroupNumber", "ProductOrTopFolder", "FileCount"])
        writer.writeheader()
        for group in sorted(group_counts, key=lambda x: int(x) if x.isdigit() else 999):
            for product, count in group_counts[group].most_common():
                writer.writerow({"GroupNumber": group, "ProductOrTopFolder": product, "FileCount": count})

    print(f"ZIPs inspected: {len(list(ZIP_DIR.glob('*.zip')))}")
    print(f"Wrote: {OUT / 'takeout_zip_product_inspection.csv'}")
    print(f"Wrote: {OUT / 'takeout_zip_group_product_summary.csv'}")
    for group in sorted(group_counts, key=lambda x: int(x) if x.isdigit() else 999):
        print(f"Group {group}:")
        for product, count in group_counts[group].most_common(8):
            print(f"  {count:6d}  {product}")


if __name__ == "__main__":
    main()
