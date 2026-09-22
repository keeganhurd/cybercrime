import csv
import hashlib
import html
import json
import re
from collections import Counter
from pathlib import Path

from PIL import Image, ExifTags


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
EVENTS = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA\Unique_Capture_Send_Events.csv")
INTEGRATED_DIR = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images"
INTEGRATED_HTML = INTEGRATED_DIR / "index_dark.html"
INTEGRATED_MEDIA = INTEGRATED_DIR / "media"
LOCATION_CSV = OUT / "Location_Audit_Google_Photos_April19_26.csv"

DEVICE_WIDTH = 1170
DEVICE_HEIGHT = 2532
DEVICE_DPI = 216
IPHONE8_DIMS = {(750, 1334), (1334, 750)}

DEVICE_CSV = OUT / "Device_Metadata_Audit_Capture_Send_Events.csv"
PHOTO_CSV = OUT / "Device_Metadata_Audit_Google_Photos_April.csv"
REPORT_MD = OUT / "Device_Metadata_Audit_Report.md"
UPDATED_HTML = INTEGRATED_DIR / "index_dark_with_device_metadata.html"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def clean_exif_value(value):
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:
            return repr(value)
    return str(value)


def image_metadata(path: Path):
    data = {
        "ReadableAsImage": "No",
        "ImageFormat": "",
        "Width": "",
        "Height": "",
        "Dimensions": "",
        "DPI": "",
        "DPIX": "",
        "DPIY": "",
        "EXIF_Make": "",
        "EXIF_Model": "",
        "EXIF_Software": "",
        "EXIF_DateTimeOriginal": "",
        "EXIF_DateTimeDigitized": "",
        "EXIF_DateTime": "",
        "EXIF_Orientation": "",
        "EXIF_AllRelevant": "",
        "MetadataError": "",
    }
    try:
        with Image.open(path) as img:
            data["ReadableAsImage"] = "Yes"
            data["ImageFormat"] = img.format or ""
            data["Width"] = img.width
            data["Height"] = img.height
            data["Dimensions"] = f"{img.width}x{img.height}"
            dpi = img.info.get("dpi") or img.info.get("resolution")
            if dpi:
                try:
                    x, y = dpi
                    data["DPIX"] = round(float(x), 3)
                    data["DPIY"] = round(float(y), 3)
                    data["DPI"] = f"{data['DPIX']}x{data['DPIY']}"
                except Exception:
                    data["DPI"] = str(dpi)
            exif = {}
            try:
                raw = img.getexif()
                for key, value in raw.items():
                    tag = ExifTags.TAGS.get(key, str(key))
                    exif[tag] = clean_exif_value(value)
            except Exception:
                exif = {}
            for tag, col in [
                ("Make", "EXIF_Make"),
                ("Model", "EXIF_Model"),
                ("Software", "EXIF_Software"),
                ("DateTimeOriginal", "EXIF_DateTimeOriginal"),
                ("DateTimeDigitized", "EXIF_DateTimeDigitized"),
                ("DateTime", "EXIF_DateTime"),
                ("Orientation", "EXIF_Orientation"),
            ]:
                data[col] = exif.get(tag, "")
            relevant = {k: v for k, v in exif.items() if k in {
                "Make", "Model", "Software", "DateTimeOriginal", "DateTimeDigitized",
                "DateTime", "Orientation", "PixelXDimension", "PixelYDimension",
                "XResolution", "YResolution", "ResolutionUnit",
            }}
            data["EXIF_AllRelevant"] = json.dumps(relevant, ensure_ascii=False)
    except Exception as exc:
        data["MetadataError"] = str(exc)
    return data


def device_class(width, height, dpi_text):
    dims = (int(width), int(height)) if str(width).isdigit() and str(height).isdigit() else None
    if not dims:
        return "Not an image / no dimensions"
    portrait_match = dims == (DEVICE_WIDTH, DEVICE_HEIGHT)
    landscape_match = dims == (DEVICE_HEIGHT, DEVICE_WIDTH)
    dpi_match = False
    for number in re.findall(r"\d+(?:\.\d+)?", str(dpi_text)):
        try:
            if abs(float(number) - DEVICE_DPI) <= 1:
                dpi_match = True
        except Exception:
            pass
    if portrait_match or landscape_match:
        if dpi_match:
            return "Matches Elijah iPhone reference dimensions and 216 DPI"
        return "Matches Elijah iPhone reference dimensions; DPI absent/different"
    if dims in IPHONE8_DIMS:
        return "Matches iPhone 8 screenshot dimensions"
    if width and height:
        return "Different dimensions from Elijah reference and iPhone 8 reference"
    return "Unknown"


def safe_file(path_value):
    if not path_value:
        return None
    path = Path(path_value)
    return path if path.exists() else None


def integrated_media_for_ce(ce):
    matches = sorted(INTEGRATED_MEDIA.glob(f"{ce}_*"))
    return matches[0] if matches else None


def load_events():
    with EVENTS.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def load_google_photo_rows():
    if not LOCATION_CSV.exists():
        return []
    with LOCATION_CSV.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, headers):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def build_card_box(row):
    match_class = "device-strong" if row["DeviceDimensionAssessment"].startswith("Matches Elijah") else "device-neutral"
    return f"""
          <div class="device-box {match_class}">
            <h4>Device / Image Metadata</h4>
            <div class="device-grid">
              <div><span>Dimensions</span><b>{esc(row['Dimensions'] or 'N/A')}</b></div>
              <div><span>DPI</span><b>{esc(row['DPI'] or 'N/A')}</b></div>
              <div><span>Format</span><b>{esc(row['ImageFormat'] or 'N/A')}</b></div>
              <div><span>Device match</span><b>{esc(row['DeviceDimensionAssessment'])}</b></div>
            </div>
            <p>{esc(row['DeviceMetadataPlainEnglish'])}</p>
          </div>
"""


def update_html(event_rows, summary_text):
    if not INTEGRATED_HTML.exists():
        return
    text = INTEGRATED_HTML.read_text(encoding="utf-8", errors="replace")
    if "Device Metadata Audit" in text:
        # Avoid stacking duplicate sections if rerun.
        text = re.sub(r"\n\s*<section class=\"device-summary\".*?</section>\s*", "\n", text, flags=re.S)
        text = re.sub(r"\n\s*<div class=\"device-box .*?</div>\s*</div>\s*</div>\s*<p>", "\n<p>", text, flags=re.S)
    css = """
.device-summary{background:#111827;border:1px solid #334155;border-left:8px solid #38bdf8;border-radius:8px;padding:14px;margin:16px 0}
.device-box{background:#0b1220;border:1px solid #334155;border-radius:8px;padding:12px;margin:12px 0}
.device-box h4{margin:0 0 8px;color:#bae6fd}
.device-strong{border-left:7px solid #22c55e}.device-neutral{border-left:7px solid #94a3b8}
.device-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px}
.device-grid div{background:#111827;border:1px solid #243244;border-radius:6px;padding:8px}
.device-grid span{display:block;color:#93a4b8;font-size:12px}.device-grid b{color:#e5edf5;font-size:14px}
"""
    text = text.replace("</style>", css + "\n</style>", 1)
    summary_html = f"""
  <section class="device-summary" id="device-metadata-audit">
    <h2>Device Metadata Audit</h2>
    <p>{esc(summary_text)}</p>
    <p><a href="../../Device_Metadata_Audit_Report.md">Open source-tracked device metadata report</a> | <a href="../../Device_Metadata_Audit_Capture_Send_Events.csv">Open CSV</a></p>
  </section>
"""
    text = text.replace("<main>", "<main>\n" + summary_html, 1)
    by_ce = {row["CanonicalEventId"]: row for row in event_rows}

    def replace_section(match):
        section = match.group(0)
        ce = match.group(1)
        row = by_ce.get(ce)
        if not row or row["ReadableAsImage"] != "Yes":
            return section
        insertion = build_card_box(row)
        target = '<div class="description">'
        idx = section.find(target)
        if idx == -1:
            return section
        # Insert before the first google/session block after description.
        gidx = section.find('<div class="google-box"', idx)
        if gidx == -1:
            grid_idx = section.find('<div class="grid">', idx)
            gidx = grid_idx if grid_idx != -1 else idx
        return section[:gidx] + insertion + section[gidx:]

    text = re.sub(
        r'<section class="event-card" id="(CE-\d{3})">.*?</section>',
        replace_section,
        text,
        flags=re.S,
    )
    UPDATED_HTML.write_text(text, encoding="utf-8")


def main():
    events = load_events()
    event_rows = []
    hash_to_ce = {}
    for ev in events:
        ce = ev.get("CanonicalEventId", "")
        media = integrated_media_for_ce(ce) or safe_file(ev.get("HtmlMediaFilePath")) or safe_file(ev.get("TimestampedScreenshotFilePath"))
        row = {
            "CanonicalEventId": ce,
            "PrimaryExhibitNumber": ev.get("PrimaryExhibitNumber", ""),
            "EventType": ev.get("EventType", ""),
            "CaptureTimestamp": ev.get("ScreenshotFilenameTimestamp", ""),
            "TextedTimestamp": ev.get("MessagesHtmlTextedToMomTimestamp", ""),
            "ElapsedSeconds": ev.get("ElapsedSeconds", ""),
            "ConversationContact": ev.get("ConversationContact", ""),
            "ImagePathScanned": str(media) if media else "",
            "FileName": media.name if media else "",
            "FileSize": media.stat().st_size if media and media.exists() else "",
            "SHA256": "",
        }
        if media and media.exists() and media.is_file():
            try:
                row["SHA256"] = sha256(media)
                hash_to_ce.setdefault(row["SHA256"], []).append(ce)
            except Exception:
                pass
            row.update(image_metadata(media))
        else:
            row.update(image_metadata(Path("__missing__")))
        row["DeviceDimensionAssessment"] = device_class(row.get("Width"), row.get("Height"), row.get("DPI"))
        if row["DeviceDimensionAssessment"].startswith("Matches Elijah"):
            row["DeviceMetadataPlainEnglish"] = "The image pixel dimensions are consistent with the Elijah iPhone reference you provided (1170 x 2532). If DPI is 216, that also matches the reference. This supports device-class consistency but does not by itself identify the physical user."
        elif "iPhone 8" in row["DeviceDimensionAssessment"]:
            row["DeviceMetadataPlainEnglish"] = "The image dimensions are consistent with an iPhone 8 screenshot size, not the Elijah iPhone reference dimensions."
        else:
            row["DeviceMetadataPlainEnglish"] = "The file does not match the Elijah iPhone reference dimensions, or dimensions were not available."
        event_rows.append(row)

    photo_rows_out = []
    for loc in load_google_photo_rows():
        media = safe_file(loc.get("MediaPath"))
        row = dict(loc)
        row["MediaSHA256"] = ""
        if media and media.exists():
            try:
                row["MediaSHA256"] = sha256(media)
                row.update(image_metadata(media))
            except Exception as exc:
                row["MetadataError"] = str(exc)
        else:
            row.update(image_metadata(Path("__missing__")))
        row["DeviceDimensionAssessment"] = device_class(row.get("Width"), row.get("Height"), row.get("DPI"))
        row["HashMatchedCaptureSendEvents"] = "; ".join(hash_to_ce.get(row["MediaSHA256"], []))
        photo_rows_out.append(row)

    event_headers = [
        "CanonicalEventId", "PrimaryExhibitNumber", "EventType", "CaptureTimestamp",
        "TextedTimestamp", "ElapsedSeconds", "ConversationContact", "ImagePathScanned",
        "FileName", "FileSize", "SHA256", "ReadableAsImage", "ImageFormat", "Width",
        "Height", "Dimensions", "DPI", "DPIX", "DPIY", "DeviceDimensionAssessment",
        "DeviceMetadataPlainEnglish", "EXIF_Make", "EXIF_Model", "EXIF_Software",
        "EXIF_DateTimeOriginal", "EXIF_DateTimeDigitized", "EXIF_DateTime",
        "EXIF_Orientation", "EXIF_AllRelevant", "MetadataError",
    ]
    write_csv(DEVICE_CSV, event_rows, event_headers)

    photo_headers = [
        "TimestampUTC", "Title", "PhotoTakenTime", "CreationTime", "Latitude",
        "Longitude", "HasGeoData", "GooglePhotosOrigin", "SourceZipFilename",
        "EntryPath", "ExtractedPath", "MediaPath", "MediaSHA256",
        "HashMatchedCaptureSendEvents", "ReadableAsImage", "ImageFormat", "Width",
        "Height", "Dimensions", "DPI", "DPIX", "DPIY", "DeviceDimensionAssessment",
        "EXIF_Make", "EXIF_Model", "EXIF_Software", "EXIF_DateTimeOriginal",
        "EXIF_DateTimeDigitized", "EXIF_DateTime", "EXIF_Orientation",
        "EXIF_AllRelevant", "MetadataError",
    ]
    write_csv(PHOTO_CSV, photo_rows_out, photo_headers)

    counts = Counter(r["DeviceDimensionAssessment"] for r in event_rows)
    strong = [r for r in event_rows if r["DeviceDimensionAssessment"].startswith("Matches Elijah")]
    iphone8 = [r for r in event_rows if "iPhone 8" in r["DeviceDimensionAssessment"]]
    photo_ios = [r for r in photo_rows_out if "IOS_PHONE" in r.get("GooglePhotosOrigin", "")]
    photo_matches = [r for r in photo_rows_out if r.get("HashMatchedCaptureSendEvents")]

    summary_text = (
        f"Device metadata was added from local image files. {len(strong)} capture/send image files match "
        f"the 1170 x 2532 Elijah iPhone reference dimensions; {len(iphone8)} match the iPhone 8 reference dimensions. "
        "This supports device-class consistency only; native iPhone databases are still needed for final attribution."
    )

    report = []
    report.append("# Device Metadata Audit Report\n\n")
    report.append("## Bottom Line\n\n")
    report.append(summary_text + "\n\n")
    report.append("## Capture/Send Event Dimension Counts\n\n")
    for key, count in counts.most_common():
        report.append(f"- {key}: {count}\n")
    report.append("\n## Capture/Send Events Matching 1170 x 2532 Reference\n\n")
    for row in strong:
        report.append(f"- {row['CanonicalEventId']} | {row['CaptureTimestamp']} | {row['Dimensions']} | DPI {row['DPI'] or 'N/A'} | `{row['FileName']}`\n")
    report.append("\n## Google Photos iOS Origin Rows\n\n")
    report.append(f"- Google Photos April rows with `IOS_PHONE` origin: {len(photo_ios)}\n")
    report.append(f"- Google Photos media hash-matched to CE capture/send events: {len(photo_matches)}\n")
    for row in photo_matches:
        report.append(f"  - {row['Title']} matched {row['HashMatchedCaptureSendEvents']} | {row['TimestampUTC']} | {row.get('SourceZipFilename','')}\n")
    report.append("\n## Limitations\n\n")
    report.append("- Pixel dimensions and DPI can show consistency with a device/display class, but do not alone identify who held the phone.\n")
    report.append("- Message export images may strip EXIF/Apple metadata; absence of EXIF is not proof the metadata never existed.\n")
    report.append("- Native iPhone `Photos.sqlite`, `sms.db`, attachment GUIDs, Apple/iCloud Photos metadata, and device model records remain the strongest corroboration targets.\n")
    REPORT_MD.write_text("".join(report), encoding="utf-8")

    update_html(event_rows, summary_text)
    print(f"Capture/send rows: {len(event_rows)}")
    print(f"1170x2532 matches: {len(strong)}")
    print(f"iPhone 8 dimension matches: {len(iphone8)}")
    print(f"Google Photos IOS_PHONE rows: {len(photo_ios)}")
    print(f"Google Photos hash matches to CE rows: {len(photo_matches)}")
    print(f"CSV: {DEVICE_CSV}")
    print(f"Google Photos CSV: {PHOTO_CSV}")
    print(f"Report: {REPORT_MD}")
    print(f"Updated HTML: {UPDATED_HTML}")


if __name__ == "__main__":
    main()
