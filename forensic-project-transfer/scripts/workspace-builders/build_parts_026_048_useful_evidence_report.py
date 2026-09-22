import csv
import hashlib
import html
import json
import shutil
from pathlib import Path


ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
OUT = ROOT / "_forensic_outputs"
SOURCE_MAP = OUT / "parts_026_048_source_zip_map.csv"
MEDIA_OUT = OUT / "parts_026_048_useful_media"
REPORT_HTML = OUT / "parts_026_048_useful_evidence_report.html"
REPORT_MD = OUT / "parts_026_048_useful_evidence_report.md"
REPORT_CSV = OUT / "parts_026_048_useful_evidence.csv"

SELECTED = [
    {
        "FileName": "IMG_2854.PNG",
        "Category": "Google Business/Profile customer-message screenshot",
        "WhyUseful": "Shows a Google Business/Profile-style customer message interface for Florida Crystal Well & Sprinkler, Inc. Google Photos metadata says mobileUpload deviceType IOS_PHONE and photoTakenTime Apr 23, 2024 3:34:57 PM UTC.",
        "Limitation": "This is Google Photos evidence of an uploaded screenshot/image. It is not a Google Drive access log and does not identify the physical user.",
    },
    {
        "FileName": "IMG_3092.PNG",
        "Category": "Business financing / DocuSign / bank-login context",
        "WhyUseful": "Shows a DocuSign/revenue-based financing agreement page involving HELO Payment Services LLC, fees, signature area, and bank-login/Daily ACH Program language.",
        "Limitation": "No supplemental metadata for this image was present in these ZIP parts; source ZIP and file hash are preserved, but capture time is not proven by metadata in this batch.",
    },
    {
        "FileName": "IMG_3116.PNG",
        "Category": "Navy Federal HELO business statement screenshot",
        "WhyUseful": "Shows Navy Federal statement material for HELO Payment Services LLC business checking, including transaction rows and account/statement context.",
        "Limitation": "No supplemental metadata for this image was present in these ZIP parts; source ZIP and file hash are preserved, but capture time is not proven by metadata in this batch.",
    },
    {
        "FileName": "IMG_3117.PNG",
        "Category": "Navy Federal HELO business statement screenshot",
        "WhyUseful": "Shows additional Navy Federal statement material for HELO Payment Services LLC business checking/savings and statement pages.",
        "Limitation": "No supplemental metadata for this image was present in these ZIP parts; source ZIP and file hash are preserved, but capture time is not proven by metadata in this batch.",
    },
    {
        "FileName": "IMG_2894.PNG",
        "Category": "Personal financial/credit document screenshot",
        "WhyUseful": "Shows a Citi Mastercard account/application letter addressed to Thomas K. Hurd with deposit requirement language. This is potentially financial-document context, but weaker than HELO/Navy/Google Business evidence.",
        "Limitation": "Not tied to Drive/Gmail access in these Takeout records and not one of the strongest exhibits.",
    },
]


def load_source_map():
    by_name = {}
    with SOURCE_MAP.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            name = Path(row["ExtractedPath"]).name
            by_name.setdefault(name, []).append(row)
    return by_name


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def load_metadata(media_path: Path):
    candidates = list(media_path.parent.glob(media_path.name + ".supplemental*.json"))
    if not candidates:
        return "", "", "", ""
    metadata_path = candidates[0]
    try:
        data = json.loads(metadata_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return str(metadata_path), "", "", ""
    photo_time = data.get("photoTakenTime", {}).get("formatted", "")
    creation_time = data.get("creationTime", {}).get("formatted", "")
    origin = data.get("googlePhotosOrigin", {})
    return str(metadata_path), photo_time, creation_time, json.dumps(origin, ensure_ascii=False)


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def main():
    MEDIA_OUT.mkdir(parents=True, exist_ok=True)
    by_name = load_source_map()
    rows = []
    for item in SELECTED:
        matches = by_name.get(item["FileName"], [])
        if not matches:
            continue
        source = matches[0]
        media_path = Path(source["ExtractedPath"])
        copied_name = item["FileName"]
        copied_path = MEDIA_OUT / copied_name
        shutil.copy2(media_path, copied_path)
        metadata_path, photo_time, creation_time, origin = load_metadata(media_path)
        rows.append({
            **item,
            "ExtractedPath": str(media_path),
            "CopiedMediaPath": str(copied_path),
            "SourceZip": source.get("SourceZip", ""),
            "SourceZipFilename": source.get("SourceZipFilename", ""),
            "EntryPath": source.get("EntryPath", ""),
            "EntrySize": source.get("EntrySize", ""),
            "EntryModified": source.get("EntryModified", ""),
            "SHA256": sha256(media_path),
            "SupplementalMetadataPath": metadata_path,
            "PhotoTakenTimeFromMetadata": photo_time,
            "CreationTimeFromMetadata": creation_time,
            "GooglePhotosOrigin": origin,
        })

    with REPORT_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        headers = [
            "FileName", "Category", "ExtractedPath", "CopiedMediaPath", "SourceZip",
            "SourceZipFilename", "EntryPath", "EntrySize", "EntryModified", "SHA256",
            "SupplementalMetadataPath", "PhotoTakenTimeFromMetadata",
            "CreationTimeFromMetadata", "GooglePhotosOrigin", "WhyUseful", "Limitation",
        ]
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    md = ["# Takeout Parts 026-048 Useful Evidence Report\n\n"]
    md.append("## Bottom Line\n\n")
    md.append("No direct Google Drive logs were found in ZIP parts 026-048. These parts are Google Photos content. However, several Google Photos images are useful as corroborating business/financial/account-content artifacts.\n\n")
    for row in rows:
        md.append(f"## {row['FileName']} - {row['Category']}\n\n")
        md.append(f"- Source ZIP: `{row['SourceZipFilename']}`\n")
        md.append(f"- Entry path: `{row['EntryPath']}`\n")
        md.append(f"- SHA256: `{row['SHA256']}`\n")
        if row["PhotoTakenTimeFromMetadata"]:
            md.append(f"- Google Photos photoTakenTime: {row['PhotoTakenTimeFromMetadata']}\n")
        if row["GooglePhotosOrigin"]:
            md.append(f"- Google Photos origin: `{row['GooglePhotosOrigin']}`\n")
        md.append(f"- Why useful: {row['WhyUseful']}\n")
        md.append(f"- Limitation: {row['Limitation']}\n\n")
    REPORT_MD.write_text("".join(md), encoding="utf-8")

    cards = []
    for row in rows:
        rel_media = "parts_026_048_useful_media/" + row["FileName"]
        cards.append(f"""
        <section class="card">
          <div class="media"><img src="{esc(rel_media)}" alt="{esc(row['FileName'])}"></div>
          <div class="body">
            <h2>{esc(row['FileName'])}</h2>
            <p><b>{esc(row['Category'])}</b></p>
            <p><span class="label">Source ZIP</span> {esc(row['SourceZipFilename'])}</p>
            <p><span class="label">Entry path</span> {esc(row['EntryPath'])}</p>
            <p><span class="label">SHA256</span> <code>{esc(row['SHA256'])}</code></p>
            <p><span class="label">Photo time</span> {esc(row['PhotoTakenTimeFromMetadata'] or 'Not present in this batch')}</p>
            <p><span class="label">Why useful</span> {esc(row['WhyUseful'])}</p>
            <p><span class="label">Limitation</span> {esc(row['Limitation'])}</p>
          </div>
        </section>""")
    html_doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Parts 026-048 Useful Evidence</title>
    <style>
    body{{margin:0;background:#0b0f14;color:#e5edf5;font:16px/1.5 Segoe UI,Arial,sans-serif}}
    header{{padding:22px 28px;background:#101827;border-bottom:3px solid #60a5fa}}
    main{{max-width:1280px;margin:0 auto;padding:20px}}
    h1{{margin:0;font-size:28px}} h2{{margin:0 0 8px;font-size:22px;color:#bfdbfe}}
    .summary{{background:#111827;border:1px solid #334155;border-left:8px solid #fbbf24;border-radius:8px;padding:14px;margin:16px 0}}
    .card{{display:grid;grid-template-columns:minmax(280px,42%) 1fr;gap:16px;background:#111827;border:1px solid #334155;border-radius:8px;margin:18px 0;overflow:hidden}}
    .media{{background:#05070a;display:flex;align-items:center;justify-content:center;padding:10px}}
    img{{max-width:100%;max-height:760px;object-fit:contain}}
    .body{{padding:14px 16px}} .label{{display:inline-block;color:#93c5fd;font-weight:700;min-width:110px}}
    code{{overflow-wrap:anywhere;color:#fde68a}} p{{margin:8px 0}}
    @media(max-width:900px){{.card{{grid-template-columns:1fr}}}}
    </style></head><body>
    <header><h1>Takeout Parts 026-048 Useful Evidence</h1><p>Local-only triage of newly added Takeout ZIP parts.</p></header>
    <main>
      <section class="summary"><b>Bottom line:</b> No direct Google Drive open/view/download/search logs were found in parts 026-048. These ZIPs are Google Photos content. A few images are still useful as corroborating account/business/financial-document artifacts.</section>
      {''.join(cards)}
    </main></body></html>"""
    REPORT_HTML.write_text(html_doc, encoding="utf-8")
    print(f"Useful rows: {len(rows)}")
    print(f"CSV: {REPORT_CSV}")
    print(f"HTML: {REPORT_HTML}")
    print(f"Markdown: {REPORT_MD}")


if __name__ == "__main__":
    main()
