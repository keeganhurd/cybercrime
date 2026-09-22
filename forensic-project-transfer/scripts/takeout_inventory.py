import csv
import zipfile
from pathlib import Path

ZIP_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Zips")
OUT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Access Audit April 2024")
OUT_CSV = OUT_DIR / "takeout_zip_inventory.csv"

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
    "Mail",
]

PATH_TERMS = [
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

TEXT_EXTS = {".json", ".html", ".htm", ".csv", ".txt", ".xml", ".ics", ".mbox"}


def matches(path, terms):
    low = path.lower()
    return [term for term in terms if term.lower() in low]


def priority_service(path):
    found = matches(path, PRIORITY_TERMS)
    return "; ".join(dict.fromkeys(found))


def modified_date(info):
    y, m, d, hh, mm, ss = info.date_time
    return f"{y:04d}-{m:02d}-{d:02d} {hh:02d}:{mm:02d}:{ss:02d}"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    zips = sorted(ZIP_DIR.glob("*.zip"))
    priority_count = 0
    rows = 0

    with OUT_CSV.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "ZipFile",
                "EntryPath",
                "UncompressedSize",
                "CompressedSize",
                "ModifiedDate",
                "PriorityService",
                "IsLikelyText",
                "MatchedPathTerms",
            ],
        )
        writer.writeheader()
        for zip_path in zips:
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    for info in zf.infolist():
                        service = priority_service(info.filename)
                        if service:
                            priority_count += 1
                        writer.writerow(
                            {
                                "ZipFile": str(zip_path),
                                "EntryPath": info.filename,
                                "UncompressedSize": info.file_size,
                                "CompressedSize": info.compress_size,
                                "ModifiedDate": modified_date(info),
                                "PriorityService": service,
                                "IsLikelyText": Path(info.filename).suffix.lower() in TEXT_EXTS,
                                "MatchedPathTerms": "; ".join(matches(info.filename, PATH_TERMS)),
                            }
                        )
                        rows += 1
            except zipfile.BadZipFile as exc:
                writer.writerow(
                    {
                        "ZipFile": str(zip_path),
                        "EntryPath": f"ERROR: BadZipFile: {exc}",
                        "UncompressedSize": "",
                        "CompressedSize": "",
                        "ModifiedDate": "",
                        "PriorityService": "",
                        "IsLikelyText": "",
                        "MatchedPathTerms": "",
                    }
                )

    print(f"ZIPs scanned: {len(zips)}")
    print(f"Entries inventoried: {rows}")
    print(f"Priority entries found: {priority_count}")
    print(f"Inventory CSV: {OUT_CSV}")


if __name__ == "__main__":
    main()
