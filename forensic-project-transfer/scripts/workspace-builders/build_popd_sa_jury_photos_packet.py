import csv
import html
import json
import re
import shutil
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path


OUT_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
PACKET_DIR = OUT_ROOT / "POPD_SA_Jury_Photos_Backup_Sequence"
MEDIA_DIR = PACKET_DIR / "media"

PHOTOS_CORR = OUT_ROOT / "Google_Photos_Phone_Artifact_Corroboration.csv"
DEVICE_AUDIT = OUT_ROOT / "Device_Metadata_Audit_Capture_Send_Events.csv"
UNIQUE_EVENTS = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet\Unique_Capture_Send_Events.csv")
MASTER_TIMELINE = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet\Master_Timeline.csv")
ZIP_SUMMARY = OUT_ROOT / "current_takeout_zips_extraction_summary.csv"
ZIP_PRODUCTS = OUT_ROOT / "takeout_zip_group_product_summary.csv"
LOCATION_AUDIT = OUT_ROOT / "Location_Audit_Google_Photos_April19_26.csv"
MYACTIVITY_EVENTS = OUT_ROOT / "myactivity_events_apr19_26.csv"
TIMELINE_SETTINGS = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout\Timeline\Settings.json")
TAKEOUT_ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\Takeout")
GOOGLE_PHOTOS_ROOT = TAKEOUT_ROOT / "Google Photos"

REFERENCE_POINTS = {
    "6275 S. Williamson GPS cluster": (29.063975, -81.0251833),
}

ROBIN_APT_APPROX = (29.0639722, -81.0251944)
WILLIAMSON_LABEL = "6275 S. Williamson GPS cluster"
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".heic", ".heif", ".gif", ".webp", ".tif", ".tiff", ".mov", ".mp4"}


def read_csv(path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_dt(value):
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def event_dt(row):
    return parse_dt(
        row.get("CaptureTimeEastern")
        or row.get("MessagesHtmlTextedToMomTimestamp")
        or row.get("TextedTimeEastern")
        or row.get("Timestamp")
        or ""
    ) or datetime.max


def safe_name(value):
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "file")
    return value[:180].strip("._") or "file"


def trunc(value, limit=320):
    value = " ".join((value or "").split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "..."


def extract_search_term(description):
    match = re.search(r"Searched for (.*?) \| [A-Z][a-z]{2} \d{1,2}, \d{4}", description or "")
    if match:
        return match.group(1).strip()
    return ""


def load_relevant_google_activity():
    rows = []
    priority_terms = [
        "elijah", "helo", "ein", "navy federal", "voided check", "docs.google",
        "gavin", "jonathan", "ariana", "venmo", "google drive ocr",
    ]
    for row in read_csv(MYACTIVITY_EVENTS):
        service = row.get("Google Service", "")
        description = row.get("Description", "")
        text = f"{service} {row.get('Event Type', '')} {description}".lower()
        if service not in {"Gmail", "Search", "Drive", "Google Business Profile"}:
            continue
        if not any(term in text for term in priority_terms):
            continue
        dt = parse_dt(row.get("Timestamp"))
        if not dt:
            continue
        if not (datetime(2024, 4, 19, 0, 0) <= dt <= datetime(2024, 4, 26, 23, 59, 59)):
            continue
        term = extract_search_term(description)
        neutral_note = neutral_google_activity_note(service, row.get("Event Type", ""), term, description)
        rows.append({
            **row,
            "_DT": dt,
            "_Term": term,
            "_Short": f"{service} {row.get('Event Type', '')}: {term or description}",
            "_NeutralNote": neutral_note,
        })
    return sorted(rows, key=lambda r: r["_DT"])


def neutral_google_activity_note(service, event_type, term, description):
    text = f"{service} {event_type} {term} {description}".lower()
    neutral_needles = [
        "google drive ocr",
        "navy federal orlando",
        "navy federal credit union",
        "winter park, fl branch",
        "winter park fl branch",
    ]
    if any(needle in text for needle in neutral_needles):
        return "Neutral account activity / not attributed. Thomas reports this may have been authorized activity by him."
    return ""


def seconds_between(a, b):
    if not a or not b or a == datetime.max or b == datetime.max:
        return None
    return int((b - a).total_seconds())


def human_delta(seconds):
    if seconds is None:
        return ""
    sign = "after" if seconds >= 0 else "before"
    seconds = abs(seconds)
    if seconds < 90:
        value = f"{seconds} sec"
    elif seconds < 7200:
        value = f"{seconds / 60:.1f} min"
    else:
        value = f"{seconds / 3600:.1f} hr"
    return f"{value} {sign}"


def esc(value):
    return html.escape(str(value or ""))


def syntax_label(text):
    raw = str(text or "")
    low = raw.lower()
    cls = "action-search"
    if "gmail" in low:
        cls = "action-gmail"
    elif "screenshot" in low:
        cls = "action-screenshot"
    elif "pdf" in low or "document transmission" in low:
        cls = "action-pdf"
    elif "visited" in low or "open" in low:
        cls = "action-search"
    return f'<span class="{cls}">{esc(raw)}</span>'


def syntax_description(text):
    value = esc(text)
    replacements = [
        ("helo payment services ein", "desc-sensitive"),
        ("Helo Payment Services", "desc-sensitive"),
        ("FILE_5531.pdf", "desc-sensitive"),
        ("IRS/EIN", "desc-sensitive"),
        ("Navy Federal", "desc-sensitive"),
        ("Google Business/Profile", "desc-account"),
        ("financial/business record", "desc-sensitive"),
        ("business-financing", "desc-sensitive"),
        ("elijah hurd", "desc-term"),
        ("Jonathan", "desc-term"),
        ("Ariana", "desc-term"),
        ("Gavin", "desc-term"),
        ("bank", "desc-sensitive"),
        ("Gmail", "desc-account"),
        ("Google Drive", "desc-account"),
        ("docs.google.com", "desc-account"),
    ]
    for needle, cls in replacements:
        value = re.sub(
            re.escape(needle),
            lambda m: f'<span class="{cls}">{m.group(0)}</span>',
            value,
            flags=re.I,
        )
    return value


def int_or_none(value):
    try:
        return int(float(str(value).strip()))
    except Exception:
        return None


def float_or_none(value):
    try:
        if value in (None, ""):
            return None
        return float(str(value).strip())
    except Exception:
        return None


def normalize_match_name(value):
    name = Path(str(value or "")).name.lower()
    for suffix in (
        ".supplemental-metadata.json",
        ".supplemental.json",
        ".suppl.json",
        ".json",
    ):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
    name = re.sub(r"\s+", " ", name)
    return name.strip()


def parse_google_photo_time(value):
    if not value:
        return ""
    if isinstance(value, dict):
        value = value.get("formatted") or value.get("timestamp") or ""
    return str(value)


def gps_from_geo_dict(data):
    if not isinstance(data, dict):
        return None
    lat = float_or_none(data.get("latitude"))
    lon = float_or_none(data.get("longitude"))
    if lat is None or lon is None:
        return None
    if abs(lat) < 0.000001 and abs(lon) < 0.000001:
        return None
    return {
        "Latitude": lat,
        "Longitude": lon,
        "Altitude": data.get("altitude", ""),
    }


def parse_sidecar_gps(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    gps = gps_from_geo_dict(data.get("geoDataExif")) or gps_from_geo_dict(data.get("geoData"))
    if not gps:
        return None
    gps.update({
        "MetadataSource": "Google Photos sidecar JSON",
        "SourcePath": str(path),
        "Filename": data.get("title") or Path(path).name,
        "GooglePhotosPhotoTakenTime": parse_google_photo_time(data.get("photoTakenTime")),
        "GooglePhotosCreationTime": parse_google_photo_time(data.get("creationTime")),
    })
    return gps


def rational_to_float(value):
    try:
        if isinstance(value, tuple) and len(value) == 2:
            return float(value[0]) / float(value[1])
        if hasattr(value, "numerator") and hasattr(value, "denominator"):
            return float(value.numerator) / float(value.denominator)
        return float(value)
    except Exception:
        return None


def dms_to_decimal(values, ref):
    if not values or len(values) < 3:
        return None
    deg = rational_to_float(values[0])
    minute = rational_to_float(values[1])
    second = rational_to_float(values[2])
    if deg is None or minute is None or second is None:
        return None
    result = deg + minute / 60.0 + second / 3600.0
    if str(ref or "").upper() in {"S", "W"}:
        result *= -1
    return result


def parse_exif_gps(path):
    try:
        from PIL import Image, ExifTags
    except Exception:
        return None
    try:
        with Image.open(path) as img:
            exif = img.getexif()
            if not exif:
                return None
            gps_tag = None
            for tag_id, tag_name in ExifTags.TAGS.items():
                if tag_name == "GPSInfo":
                    gps_tag = tag_id
                    break
            gps_info = exif.get(gps_tag) if gps_tag else None
            if not gps_info:
                return None
            gps_named = {}
            for key, val in gps_info.items():
                gps_named[ExifTags.GPSTAGS.get(key, key)] = val
            lat = dms_to_decimal(gps_named.get("GPSLatitude"), gps_named.get("GPSLatitudeRef"))
            lon = dms_to_decimal(gps_named.get("GPSLongitude"), gps_named.get("GPSLongitudeRef"))
            if lat is None or lon is None:
                return None
            alt = gps_named.get("GPSAltitude", "")
            alt_val = rational_to_float(alt) if alt != "" else ""
            return {
                "Latitude": lat,
                "Longitude": lon,
                "Altitude": alt_val,
                "MetadataSource": "EXIF",
                "SourcePath": str(path),
                "Filename": Path(path).name,
            }
    except Exception:
        return None


def build_google_photos_source_index():
    index = {
        "sidecar_by_name": {},
        "image_by_name": {},
        "json_sidecars_scanned": 0,
        "images_indexed": 0,
        "gps_bearing_examples": [],
        "folders_searched": [str(GOOGLE_PHOTOS_ROOT), str(OUT_ROOT)],
    }
    if GOOGLE_PHOTOS_ROOT.exists():
        for path in GOOGLE_PHOTOS_ROOT.rglob("*"):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix == ".json":
                index["json_sidecars_scanned"] += 1
                gps = parse_sidecar_gps(path)
                keys = {normalize_match_name(path.name)}
                try:
                    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
                    if data.get("title"):
                        keys.add(normalize_match_name(data.get("title")))
                except Exception:
                    pass
                for key in keys:
                    if key:
                        index["sidecar_by_name"].setdefault(key, []).append((path, gps))
                if gps and len(index["gps_bearing_examples"]) < 12:
                    index["gps_bearing_examples"].append(gps)
            elif suffix in IMAGE_EXTS:
                index["images_indexed"] += 1
                index["image_by_name"].setdefault(normalize_match_name(path.name), []).append(path)
    return index


def apply_gps_metadata(row, source_index, summary):
    summary["matched_items_checked"] += 1
    gps = None
    lat = float_or_none(row.get("Latitude"))
    lon = float_or_none(row.get("Longitude"))
    if lat is not None and lon is not None:
        gps = {
            "Latitude": lat,
            "Longitude": lon,
            "Altitude": row.get("Altitude", ""),
            "MetadataSource": "generated analysis output",
            "SourcePath": row.get("GooglePhotosMetadataPath") or PHOTOS_CORR,
            "Filename": row.get("GooglePhotosTitle") or row.get("PhoneHtmlMediaName") or row.get("CanonicalEventId"),
            "GooglePhotosPhotoTakenTime": row.get("GooglePhotosTimeUTC") or row.get("GooglePhotosTimeEastern", ""),
            "GooglePhotosCreationTime": "",
        }

    candidate_sidecars = []
    meta_path = row.get("GooglePhotosMetadataPath")
    if meta_path and Path(meta_path).exists():
        candidate_sidecars.append(Path(meta_path))
    for value in (row.get("GooglePhotosTitle"), row.get("GooglePhotosMediaPath"), row.get("PhoneHtmlMediaName")):
        key = normalize_match_name(value)
        candidate_sidecars.extend(path for path, _ in source_index["sidecar_by_name"].get(key, []))

    if not gps:
        seen = set()
        for sidecar in candidate_sidecars:
            if sidecar in seen:
                continue
            seen.add(sidecar)
            gps = parse_sidecar_gps(sidecar)
            if gps:
                break

    if not gps:
        image_candidates = []
        media_path = row.get("GooglePhotosMediaPath")
        if media_path and Path(media_path).exists():
            image_candidates.append(Path(media_path))
        for value in (row.get("GooglePhotosTitle"), row.get("GooglePhotosMediaPath"), row.get("PhoneHtmlMediaName")):
            key = normalize_match_name(value)
            image_candidates.extend(source_index["image_by_name"].get(key, []))
        seen = set()
        for image_path in image_candidates:
            if image_path in seen:
                continue
            seen.add(image_path)
            summary["images_scanned_for_exif"] += 1
            gps = parse_exif_gps(image_path)
            if gps:
                break

    if gps:
        dist = haversine_m(float(gps["Latitude"]), float(gps["Longitude"]), ROBIN_APT_APPROX[0], ROBIN_APT_APPROX[1])
        row["_GPSLatitude"] = f"{float(gps['Latitude']):.7f}"
        row["_GPSLongitude"] = f"{float(gps['Longitude']):.7f}"
        row["_GPSAltitude"] = str(gps.get("Altitude", "") or "")
        row["_GPSDistanceMeters"] = f"{dist:.1f}"
        row["_GPSMetadataSource"] = gps.get("MetadataSource", "")
        row["_GPSSourcePath"] = str(gps.get("SourcePath", ""))
        row["_GPSFilename"] = gps.get("Filename", "")
        row["_GPSPhotoTakenTime"] = gps.get("GooglePhotosPhotoTakenTime", "")
        row["_GPSCreationTime"] = gps.get("GooglePhotosCreationTime", "")
        summary["matched_items_with_gps"] += 1
    else:
        summary["matched_items_without_gps"] += 1
    return row


def haversine_m(lat1, lon1, lat2, lon2):
    from math import asin, cos, radians, sin, sqrt

    r = 6371000.0
    phi1, phi2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(dlambda / 2) ** 2
    return 2 * r * asin(sqrt(a))


def utc_to_eastern_naive(dt):
    # April 2024 in Florida is EDT (UTC-4).
    return dt - timedelta(hours=4) if dt else None


def load_source_zip_lookup():
    lookup = {}
    for map_path in OUT_ROOT.glob("*source*map*.csv"):
        for row in read_csv(map_path):
            extracted = row.get("ExtractedPath", "")
            entry = row.get("EntryPath", "")
            zip_name = row.get("SourceZipFilename", "")
            if not zip_name:
                continue
            for key in (extracted.lower(), entry.replace("/", "\\").lower(), Path(extracted).name.lower(), Path(entry).name.lower()):
                if key and key not in lookup:
                    lookup[key] = zip_name
    return lookup


def source_zip_for(row, lookup):
    for field in ("GooglePhotosMetadataPath", "GooglePhotosMediaPath"):
        path = row.get(field, "")
        if not path:
            continue
        for key in (path.lower(), Path(path).name.lower()):
            if key in lookup:
                return lookup[key]
    title = row.get("GooglePhotosTitle", "")
    if title and title.lower() in lookup:
        return lookup[title.lower()]
    return row.get("SourceZipFilename", "")


def copy_media(src_value, event_id, label=""):
    if not src_value:
        return ""
    src = Path(src_value)
    if not src.exists() or not src.is_file():
        return ""
    suffix = src.suffix.lower() or ".bin"
    dest = MEDIA_DIR / f"{safe_name(event_id)}_{safe_name(label or src.stem)}{suffix}"
    try:
        if not dest.exists() or dest.stat().st_size != src.stat().st_size:
            shutil.copy2(src, dest)
    except Exception:
        return ""
    return "media/" + dest.name


def category_score(row):
    text = " ".join([
        row.get("_CleanCategory", ""),
        row.get("VisualDescription", ""),
        row.get("PhoneHtmlMediaName", ""),
    ]).lower()
    score = 0
    weights = {
        "irs": 8, "ein": 8, "cp 575": 8, "file_5531": 10,
        "bank": 7, "navy federal": 7, "statement": 7,
        "helo": 7, "payment services": 7,
        "gmail": 6, "keeganhurd@gmail.com": 6,
        "drive": 6, "google business": 6, "business profile": 6,
        "financial": 6, "docusign": 5, "virtue": 5,
        "id card": 5, "driver": 4,
    }
    for term, weight in weights.items():
        if term in text:
            score += weight
    delta = int_or_none(row.get("GooglePhotosMinusCaptureSeconds"))
    send = int_or_none(row.get("CaptureToTextSeconds"))
    if delta in (0, 1):
        score += 5
    if send is not None and 0 <= send <= 30:
        score += 5
    if row.get("MatchClassification", "").lower().startswith("strong"):
        score += 3
    return score


def derive_visible_categories(row):
    """Use visible/OCR text for presentation tags.

    The upstream OCR category file can over-tag rows because it was built for
    broad searching. Presentation tags need to describe what is visible in the
    specific screenshot, so derive them from the row's visual text instead.
    """
    text = " ".join([
        row.get("VisualDescription", ""),
        row.get("PhoneHtmlMediaName", ""),
        row.get("HtmlMediaFileName", ""),
    ]).lower()

    cats = []

    def has(*terms):
        return any(term in text for term in terms)

    def rx(pattern):
        return re.search(pattern, text, flags=re.I) is not None

    if has("gmail", "inbox", "standard encryption", "display images", "keeganhurd@gmail.com", "from to date"):
        cats.append("Gmail")
    if has("< drive", "google drive", "drive "):
        cats.append("Google Drive")
    if has("business profile", "sending as florida crystal", "your businesses", "google business profile"):
        cats.append("Google Business/Profile")
    if rx(r"\birs\b|\bein\b|employer identification|cp\s*575|ss[-\s]?4"):
        cats.append("IRS/EIN")
    if has("helo payment", "helo payment services", "held payment services"):
        cats.append("Helo Payment Services")
    if has("navy federal", "credit union", "routing number", "business checking", "statement of account", "bank statement"):
        cats.append("Bank / Navy Federal")
    if has("statement", "p&l", "profit", "loss", "payout", "transaction", "financing", "funding", "docusign", "contract"):
        cats.append("Financial/business record")
    if has("venmo", "paypal"):
        cats.append("Venmo/payment")
    if has("temporary custody", "formal notice", "non-consent", "vaccination", "affidavit", "notary", "grantor", "grantee"):
        cats.append("Legal/client document")
    if has("driver license", "drivers license", "driver's license", "id card", "florida id"):
        cats.append("Identity document")

    # Preserve explicit PDF/EIN classification for FILE_5531 where visual text is short.
    if "file_5531" in text:
        for cat in ("PDF attachment", "IRS/EIN", "Helo Payment Services"):
            if cat not in cats:
                cats.append(cat)

    return "; ".join(cats)


def enrich_phone_only_row(row, device_rows):
    merged = dict(row)
    device = device_rows.get(row.get("CanonicalEventId"), {})
    for key in ("DeviceDimensionAssessment", "DeviceMetadataPlainEnglish", "SHA256", "Dimensions", "DPI", "ImagePathScanned"):
        if device.get(key) and not merged.get(key):
            merged[key] = device[key]
    if not merged.get("ConversationContact"):
        merged["ConversationContact"] = "Mom"
    clean = derive_visible_categories(merged)
    merged["_CleanCategory"] = clean or merged.get("OCRSensitiveCategory", "")
    merged["_CleanTerms"] = clean or merged.get("OCRKeyTerms", "")
    merged["_Score"] = str(category_score(merged))
    merged["_SourceZip"] = "Messages HTML export / recovered phone evidence, not Google Takeout ZIP"
    src_img = merged.get("HtmlMediaFilePath") or merged.get("TimestampedScreenshotFilePath") or merged.get("ImagePathScanned")
    merged["_ImageRel"] = copy_media(src_img, merged.get("CanonicalEventId"), Path(src_img).stem if src_img else "")
    if not merged.get("MatchClassification"):
        merged["MatchClassification"] = "Phone/message timing only"
    return merged


def normalize_google_photos_match(row):
    delta = int_or_none(row.get("GooglePhotosMinusCaptureSeconds"))
    if delta is not None and delta < 0:
        row["_InvalidBackupDelta"] = "Yes"
        row["_OriginalGooglePhotosTitle"] = row.get("GooglePhotosTitle", "")
        row["_OriginalGooglePhotosTimeEastern"] = row.get("GooglePhotosTimeEastern", "")
        row["_OriginalGooglePhotosMinusCaptureSeconds"] = row.get("GooglePhotosMinusCaptureSeconds", "")
        row["_OriginalMatchClassification"] = row.get("MatchClassification", "")
        row["_OriginalGooglePhotosMediaPath"] = row.get("GooglePhotosMediaPath", "")
        row["_OriginalGooglePhotosMetadataPath"] = row.get("GooglePhotosMetadataPath", "")
        row["GooglePhotosTitle"] = ""
        row["GooglePhotosTimeEastern"] = ""
        row["GooglePhotosMinusCaptureSeconds"] = ""
        row["GooglePhotosMediaPath"] = ""
        row["GooglePhotosMetadataPath"] = ""
        row["MatchClassification"] = "No valid per-item Google Photos backup match"
    else:
        row["_InvalidBackupDelta"] = "No"
    return row


def event_sort_key(row):
    return parse_dt(row.get("CaptureTimeEastern") or row.get("MessagesHtmlTextedToMomTimestamp") or "") or datetime.max


def chip(text, cls=""):
    if not text:
        return ""
    return f'<span class="chip {cls}">{esc(text)}</span>'


def fact(label, value, cls=""):
    if value in (None, ""):
        value = "not recorded"
        cls = (cls + " muted").strip()
    return f'<div class="fact"><span class="k">{esc(label)}</span><span class="v {cls}">{esc(value)}</span></div>'


def gps_card_html(row):
    lat = float_or_none(row.get("_GPSLatitude"))
    lon = float_or_none(row.get("_GPSLongitude"))
    if lat is None or lon is None:
        return ""
    return f"""
    <div class="gpsbox">
      <p><span class="label">Google Photos GPS metadata:</span></p>
      <p>Latitude: <span class="codekey">{esc(f"{lat:.7f}")}</span>; Longitude: <span class="codekey">{esc(f"{lon:.7f}")}</span>; approximate location label: <span class="codekey">{esc(WILLIAMSON_LABEL)}</span>; distance from 6275 S. Williamson reference coordinate: <span class="codekey">{esc(row.get("_GPSDistanceMeters"))} meters</span>.</p>
      <p>Source: <span class="codekey">{esc(row.get("_GPSMetadataSource"))}</span>; source file: <span class="codekey">{esc(row.get("_GPSSourcePath"))}</span></p>
      <p class="muted">GPS metadata is device/account location context only. It does not by itself identify the physical user.</p>
    </div>
    """


def card(row, index=None, highlight=False):
    event_id = row.get("CanonicalEventId", "")
    exhibit = row.get("Exhibit") or row.get("PrimaryExhibitNumber", "")
    event_type = row.get("EventType") or "Screenshot + backup + message sequence"
    image_rel = row.get("_ImageRel", "")
    pdf_rel = row.get("_PdfRel", "")
    score = row.get("_Score", "")
    source_zip = row.get("_SourceZip", "")
    title_bits = [event_id, exhibit, event_type]
    title = " / ".join([b for b in title_bits if b])

    delta = row.get("GooglePhotosMinusCaptureSeconds", "")
    send_delta = row.get("CaptureToTextSeconds") or row.get("ElapsedSeconds", "")
    backup_phrase = "not matched"
    if delta != "":
        backup_phrase = f"{delta} sec after capture" if not str(delta).startswith("-") else f"{delta} sec from filename time"
    elif row.get("_InvalidBackupDelta") == "Yes":
        backup_phrase = "no valid per-item match; prior Google Photos item only"
    send_phrase = f"{send_delta} sec after capture" if send_delta != "" else "not recorded"

    visual = trunc(row.get("VisualDescription", ""), 360)
    category = row.get("_CleanCategory", "") or row.get("OCRSensitiveCategory", "")
    terms = row.get("_CleanTerms", "") or row.get("OCRKeyTerms", "")
    term_parts = []
    for part in re.split(r";|,", ";".join([category, terms])):
        part = part.strip()
        if part and part not in term_parts:
            term_parts.append(part)
    limitation = row.get("Limitation") or "This record supports timing/content/device consistency, but does not by itself identify the physical user."
    if row.get("_InvalidBackupDelta") == "Yes":
        why = "This screenshot remains part of the phone capture-to-message sequence, but the current Google Photos row does not prove this exact screenshot backed up. The previous report linked it to an earlier Google Photos item, which created an impossible negative delta."
    else:
        why = row.get("WhyItMatters") or "The capture time, Google Photos backup time, and message timestamp are close together, supporting a capture/transmit sequence rather than an old loose photo being found later."

    img_block = ""
    if image_rel:
        img_block = f'<a href="{esc(image_rel)}" target="_blank"><img src="{esc(image_rel)}" alt="{esc(title)}"></a>'
    elif pdf_rel:
        img_block = f'''
        <div class="pdfpreview">
          <object data="{esc(pdf_rel)}#view=FitH" type="application/pdf">
            <div class="pdfbox"><div class="pdficon">PDF</div><a href="{esc(pdf_rel)}" target="_blank">{esc(row.get("HtmlMediaFileName") or "Open PDF copy")}</a></div>
          </object>
          <a class="openfile" href="{esc(pdf_rel)}" target="_blank">{esc(row.get("HtmlMediaFileName") or "Open PDF copy")}</a>
        </div>
        '''
    else:
        img_block = '<div class="noimg">No preview copied</div>'

    tags = "".join([
        chip(category, "cat") if category else "",
        chip(row.get("MatchClassification", ""), "match") if row.get("MatchClassification") else "",
        chip("IOS_PHONE backup", "ios") if row.get("GooglePhotosTimeEastern") and "IOS_PHONE" in row.get("GooglePhotosOrigin", "") else "",
        chip(row.get("DeviceDimensionAssessment", ""), "dim") if row.get("DeviceDimensionAssessment") else "",
    ])

    return f"""
    <article class="card {'critical' if highlight else ''}" id="{esc(event_id)}">
      <div class="card-head">
        <div>
          <div class="ordinal">{'#' + str(index) if index else ''}</div>
          <h3>{esc(title)}</h3>
          <div class="tags">{tags}</div>
        </div>
        <div class="score">weight {esc(score)}</div>
      </div>
      <div class="card-grid">
        <div class="facts">
          {fact('capture', row.get('CaptureTimeEastern') or row.get('ScreenshotFilenameTimestamp'))}
          {fact('Google Photos backup', row.get('GooglePhotosTimeEastern'))}
          {fact('backup delta', backup_phrase, 'hot')}
          {fact('texted / linked', row.get('TextedTimeEastern') or row.get('MessagesHtmlTextedToMomTimestamp'))}
          {fact('capture-to-send', send_phrase, 'hot')}
          {fact('conversation', row.get('ConversationContact') or 'Mom')}
          {fact('image dimensions', row.get('PhoneImageDimensions') or row.get('Dimensions'))}
          {fact('phone image DPI', row.get('PhoneImageDPI') or row.get('DPI'))}
          {fact('source ZIP', source_zip)}
        </div>
        <div class="media">{img_block}</div>
      </div>
      <div class="explain">
        <p>{esc(why)}</p>
        {gps_card_html(row)}
        <p><b>Visible content:</b> {esc(visual)}</p>
        <p><b>Terms/categories:</b> {esc('; '.join(term_parts))}</p>
        <p><b>What this does not prove by itself:</b> {esc(limitation)}</p>
      </div>
      <details>
        <summary>Source paths and authentication notes</summary>
        <div class="source">
          <div>{fact('phone media path', row.get('PhoneHtmlMediaPath') or row.get('ImagePathScanned') or row.get('HtmlMediaFilePath'))}</div>
          <div>{fact('Google Photos media path', row.get('GooglePhotosMediaPath'))}</div>
          <div>{fact('Google Photos metadata JSON', row.get('GooglePhotosMetadataPath'))}</div>
          <div>{fact('prior Google Photos row ignored', (row.get('_OriginalGooglePhotosTitle', '') + ' at ' + row.get('_OriginalGooglePhotosTimeEastern', '')).strip(' at') if row.get('_InvalidBackupDelta') == 'Yes' else '')}</div>
          <div>{fact('SHA256', row.get('SHA256') or row.get('PrimarySHA256'))}</div>
          <div>{fact('native confirmation needed', row.get('NativeConfirmationNeeded') or 'sms.db, Photos database, iCloud/Google server-side provider logs, and device possession/location records.')}</div>
        </div>
      </details>
    </article>
    """


def sessionize(rows, gap_minutes=30):
    sessions = []
    current = []
    last = None
    for row in sorted(rows, key=event_sort_key):
        dt = event_sort_key(row)
        if dt == datetime.max:
            continue
        if current and last and (dt - last).total_seconds() > gap_minutes * 60:
            sessions.append(current)
            current = []
        current.append(row)
        last = dt
    if current:
        sessions.append(current)
    return sessions


def build_location_summary_html():
    rows = []
    for row in read_csv(LOCATION_AUDIT):
        lat = float_or_none(row.get("Latitude"))
        lon = float_or_none(row.get("Longitude"))
        if lat is None or lon is None:
            continue
        utc = parse_dt(row.get("TimestampUTC"))
        eastern = utc_to_eastern_naive(utc)
        distances = {name: haversine_m(lat, lon, ref[0], ref[1]) for name, ref in REFERENCE_POINTS.items()}
        nearest_name, nearest_m = sorted(distances.items(), key=lambda item: item[1])[0]
        rows.append({
            **row,
            "_UTC": utc,
            "_Eastern": eastern,
            "_Lat": lat,
            "_Lon": lon,
            "_Nearest": nearest_name,
            "_NearestMeters": nearest_m,
            "_WilliamsonMeters": distances[WILLIAMSON_LABEL],
        })

    main_start = datetime(2024, 4, 25, 12, 23, 36)
    main_end = datetime(2024, 4, 25, 14, 11, 32)
    during_main = [r for r in rows if r["_Eastern"] and main_start <= r["_Eastern"] <= main_end]
    williamson_window = [
        r for r in rows
        if r["_Eastern"] and datetime(2024, 4, 25, 0, 0, 0) <= r["_Eastern"] <= datetime(2024, 4, 25, 23, 59, 59)
        and r["_WilliamsonMeters"] <= 100
    ]

    def loc_row(r):
        return f"""
        <tr>
          <td class="time">{esc(r['_Eastern'].strftime('%Y-%m-%d'))}<br><b>{esc(r['_Eastern'].strftime('%I:%M:%S %p'))}</b></td>
          <td>{esc(r.get('Title'))}</td>
          <td>{esc(f"{r['_Lat']:.7f}")}</td>
          <td>{esc(f"{r['_Lon']:.7f}")}</td>
          <td>{esc(WILLIAMSON_LABEL)}</td>
          <td>{esc(f"{r['_WilliamsonMeters']:.1f} m")}</td>
          <td>Google Photos sidecar JSON</td>
          <td>{esc(r.get('ExtractedPath'))}</td>
        </tr>
        """

    williamson_rows = "".join(loc_row(r) for r in williamson_window) or '<tr><td colspan="8">No 6275 S. Williamson GPS cluster point found in this window.</td></tr>'

    if during_main:
        key = during_main[0]
        main_statement = (
            f"During the main April 25, 2024 screenshot/message session, Google Photos metadata includes a GPS-bearing iOS upload "
            f"({key.get('Title')}) at {key['_Eastern'].strftime('%I:%M:%S %p')} Eastern, "
            f"approximately {key['_WilliamsonMeters']:.1f} meters from the {WILLIAMSON_LABEL}."
        )
    else:
        main_statement = "No GPS-bearing Google Photos item falls inside the main April 25 screenshot session."

    return f"""
  <section id="location-context">
    <h2>Location Context During Main April 25 Session</h2>
    <div class="plain">
      <p><span class="label">Calendar note:</span> April 25, 2024 was a Thursday.</p>
      <p><span class="label">Main session window:</span> The main business/financial screenshot and message sequence occurred on April 25, 2024 from approximately <span class="time">12:23:36 PM</span> to <span class="time">2:11:32 PM</span> Eastern.</p>
      <p><span class="label">GPS-bearing Google Photos item:</span> Google Photos metadata includes a GPS-bearing iOS upload, <span class="codekey">IMG_2859.JPG</span>, at approximately <span class="time">12:31:19 PM</span> Eastern during that same session window. The coordinates for that item are approximately <span class="codekey">29.0639750, -81.0251833</span>, which places it at or near the <span class="codekey">6275 S. Williamson GPS cluster</span>.</p>
      <p><span class="label">Reported school and time-sharing context:</span> Thomas Hurd reports that April 25, 2024 was Respondent/Mother&apos;s time-sharing day. Thomas further reports that Elijah&apos;s school did not allow phones on campus, even turned off in a backpack, and that Elijah normally left his phone with a parent while attending school. Thomas also reports that he did not receive a school absence notification for Elijah that day, which is consistent with Elijah being present at school.</p>
      <p><span class="label">Investigative significance:</span> If school attendance records, campus records, bus records, Apple/iCloud records, Google records, or provider records confirm that Elijah was at school while the iPhone or Google Photos activity was located near the <span class="codekey">6275 S. Williamson GPS cluster</span>, that would support the inference that the activity was not physically performed by Elijah.</p>
      <p><span class="label">Evidence boundary:</span> The GPS-bearing Google Photos item does not by itself identify the physical user of the phone. It is location-and-time context that should be checked against native iPhone records, Apple/iCloud records, Google provider records, school attendance records, and any available account/device logs.</p>
    </div>
    <h3>GPS-Bearing Google Photos Items Near 6275 S. Williamson on April 25, 2024</h3>
    <table><thead><tr><th>Time Eastern</th><th>Google Photos Item</th><th>Latitude</th><th>Longitude</th><th>Location Label</th><th>Distance From Reference Point</th><th>Metadata Source</th><th>Source Path</th></tr></thead><tbody>{williamson_rows}</tbody></table>
  </section>
    """


def write_gps_provenance_investigation(corr_rows):
    target_names = {
        "IMG_2859.JPG",
        "IMG_2862.JPG",
        "IMG_2863.JPG",
        "IMG_2864.JPG",
        "IMG_2865.JPG",
        "IMG_2866.JPG",
        "IMG_2867.JPG",
        "IMG_2868.JPG",
    }
    matched_titles = {normalize_match_name(r.get("GooglePhotosTitle")) for r in corr_rows if r.get("GooglePhotosTitle")}
    matched_titles.update(normalize_match_name(r.get("GooglePhotosMediaPath")) for r in corr_rows if r.get("GooglePhotosMediaPath"))

    searched_roots = [
        Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted"),
        TAKEOUT_ROOT,
        GOOGLE_PHOTOS_ROOT,
        GOOGLE_PHOTOS_ROOT / "Photos from 2024",
        OUT_ROOT,
        PACKET_DIR,
    ]
    searched_key_files = [
        LOCATION_AUDIT,
        PHOTOS_CORR,
        PACKET_DIR / "index_chronological_story.html",
        PACKET_DIR / "gps_metadata_search_summary.txt",
    ]

    rows = []
    for row in read_csv(LOCATION_AUDIT):
        title = row.get("Title", "")
        if title not in target_names:
            continue
        lat = float_or_none(row.get("Latitude"))
        lon = float_or_none(row.get("Longitude"))
        if lat is None or lon is None:
            continue
        source_path = Path(row.get("ExtractedPath", ""))
        sidecar_gps = parse_sidecar_gps(source_path) if source_path.exists() else None
        utc = parse_dt(row.get("TimestampUTC"))
        eastern = utc_to_eastern_naive(utc)
        dist = haversine_m(lat, lon, REFERENCE_POINTS[WILLIAMSON_LABEL][0], REFERENCE_POINTS[WILLIAMSON_LABEL][1])
        is_matched = normalize_match_name(title) in matched_titles
        main_start = datetime(2024, 4, 25, 12, 23, 36)
        main_end = datetime(2024, 4, 25, 14, 11, 32)
        relation = "nearby Google Photos/iOS item during the main April 25 session" if eastern and main_start <= eastern <= main_end else "GPS-bearing Google Photos/iOS item from April 25 outside the main noon-to-2 PM screenshot session"
        rows.append({
            "title": title,
            "timestamp_utc": row.get("TimestampUTC", ""),
            "timestamp_eastern": eastern.strftime("%Y-%m-%d %I:%M:%S %p") if eastern else "",
            "photo_taken": row.get("PhotoTakenTime", ""),
            "creation": row.get("CreationTime", ""),
            "lat": f"{lat:.7f}",
            "lon": f"{lon:.7f}",
            "altitude": "" if not sidecar_gps else str(sidecar_gps.get("Altitude", "")),
            "distance": f"{dist:.1f}",
            "metadata_source": "Google Photos sidecar JSON" if sidecar_gps else "intermediate output - source verification needed",
            "sidecar": str(source_path),
            "media": row.get("MediaPath", ""),
            "matched": "Yes" if is_matched else "No",
            "relation": relation,
        })

    exact_files_found = set()
    for row in rows:
        exact_files_found.add(row["sidecar"])
        exact_files_found.add(row["media"])
    for key_file in searched_key_files:
        if key_file.exists():
            exact_files_found.add(str(key_file))

    lines = []
    lines.append("GPS Provenance Investigation")
    lines.append("")
    lines.append("Question investigated:")
    lines.append("- Prior analysis showed Google Photos GPS metadata, while the latest card-level search reported 0 matched screenshot items with usable GPS.")
    lines.append("")
    lines.append("Bottom line:")
    lines.append("- The prior GPS/location data came from separate Google Photos items in the same Google Photos/iOS dataset, especially IMG_2859.JPG and IMG_2862.JPG through IMG_2868.JPG.")
    lines.append("- For the confirmed items below, the source is Google Photos sidecar JSON containing geoData and geoDataExif.")
    lines.append("- These GPS-bearing items are not among the 68 matched screenshot/Google Photos evidence rows in Google_Photos_Phone_Artifact_Corroboration.csv.")
    lines.append("- The latest generator correctly found 0 usable per-item GPS records for the matched screenshot rows because it was checking the matched screenshot/Google Photos evidence items, not nearby GPS-bearing photos from the same Google Photos/iOS dataset.")
    lines.append("- The GPS-bearing items remain potentially useful as session-location context, not per-screenshot GPS proof.")
    lines.append("")
    lines.append("Folders searched / reviewed:")
    for root in searched_roots:
        lines.append(f"- {root}")
    lines.append("")
    lines.append("Key files reviewed:")
    for key_file in searched_key_files:
        lines.append(f"- {key_file} ({'present' if key_file.exists() else 'not found'})")
    lines.append("")
    lines.append("Exact files where targeted GPS/location terms or source data were found:")
    for path in sorted(p for p in exact_files_found if p):
        lines.append(f"- {path}")
    lines.append("")
    lines.append("GPS-bearing Google Photos items confirmed:")
    if not rows:
        lines.append("- No targeted GPS-bearing items were confirmed from the source files.")
    for row in rows:
        lines.append("")
        lines.append(f"Filename: {row['title']}")
        lines.append(f"Timestamp UTC: {row['timestamp_utc']}")
        lines.append(f"Timestamp Eastern: {row['timestamp_eastern']}")
        lines.append(f"Google Photos photoTakenTime: {row['photo_taken']}")
        lines.append(f"Google Photos creationTime: {row['creation']}")
        lines.append(f"Latitude: {row['lat']}")
        lines.append(f"Longitude: {row['lon']}")
        lines.append(f"Altitude: {row['altitude']}")
        lines.append(f"Distance from 6275 S. Williamson reference coordinate: {row['distance']} meters")
        lines.append(f"Metadata source type: {row['metadata_source']}")
        lines.append(f"Source sidecar JSON path: {row['sidecar']}")
        lines.append(f"Source image path: {row['media']}")
        lines.append(f"One of 68 matched screenshot/Google Photos items: {row['matched']}")
        lines.append(f"Relationship to screenshot evidence: {row['relation']}")
    lines.append("")
    lines.append("Recommended packet wording:")
    lines.append("No usable per-item GPS metadata was found for the matched screenshot/Google Photos evidence items. However, separate GPS-bearing Google Photos items from the same Google Photos/iOS dataset appear during the same April 25, 2024 session window. Those GPS-bearing items provide session-location context, not per-screenshot GPS proof.")
    lines.append("")
    lines.append("Careful explanatory note:")
    lines.append("The GPS-bearing Google Photos items are not the matched screenshots themselves unless specifically identified as such. They are used only as session-location context. They do not identify the physical user of the phone. They should be verified through native iPhone records, Apple/iCloud records, Google provider records, school attendance records, and any available account/device logs.")
    lines.append("")
    lines.append("Provenance conclusion:")
    lines.append("- Prior GPS came from Google Photos sidecar JSON and the intermediate Location_Audit_Google_Photos_April19_26.csv generated from those sidecars.")
    lines.append("- It was not hardcoded as the only source, although the report computes distance to a local reference coordinate for presentation.")
    lines.append("- It was not found as per-item GPS for the matched screenshots.")
    lines.append("- It supports session-location context only and requires independent verification before any physical-user conclusion.")

    (PACKET_DIR / "gps_provenance_investigation.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    PACKET_DIR.mkdir(parents=True, exist_ok=True)
    MEDIA_DIR.mkdir(parents=True, exist_ok=True)

    lookup = load_source_zip_lookup()
    corr_rows = read_csv(PHOTOS_CORR)
    write_gps_provenance_investigation(corr_rows)
    device_rows = {r.get("CanonicalEventId"): r for r in read_csv(DEVICE_AUDIT)}
    gps_source_index = build_google_photos_source_index()
    gps_summary = {
        "folders_searched": gps_source_index["folders_searched"],
        "json_sidecars_scanned": gps_source_index["json_sidecars_scanned"],
        "images_indexed": gps_source_index["images_indexed"],
        "images_scanned_for_exif": 0,
        "matched_items_checked": 0,
        "matched_items_with_gps": 0,
        "matched_items_without_gps": 0,
        "gps_bearing_examples": gps_source_index["gps_bearing_examples"],
    }

    enriched = []
    for row in corr_rows:
        merged = dict(row)
        merged = normalize_google_photos_match(merged)
        merged = apply_gps_metadata(merged, gps_source_index, gps_summary)
        device = device_rows.get(row.get("CanonicalEventId"), {})
        for key in ("DeviceDimensionAssessment", "DeviceMetadataPlainEnglish", "SHA256", "Dimensions", "DPI", "ImagePathScanned"):
            if device.get(key) and not merged.get(key):
                merged[key] = device[key]
        clean = derive_visible_categories(merged)
        merged["_CleanCategory"] = clean
        merged["_CleanTerms"] = clean
        merged["_Score"] = str(category_score(merged))
        merged["_SourceZip"] = source_zip_for(merged, lookup)
        src_img = merged.get("PhoneHtmlMediaPath") or merged.get("ImagePathScanned") or merged.get("GooglePhotosMediaPath")
        merged["_ImageRel"] = copy_media(src_img, merged.get("CanonicalEventId"), Path(src_img).stem if src_img else "")
        enriched.append(merged)

    unique_events = read_csv(UNIQUE_EVENTS)
    pdf_rows = [r for r in unique_events if "FILE_5531" in " ".join(r.values())]
    pdf_cards = []
    for row in pdf_rows[:1]:
        merged = dict(row)
        clean = derive_visible_categories(merged)
        merged["_CleanCategory"] = clean or merged.get("OCRSensitiveCategory", "")
        merged["_CleanTerms"] = clean or merged.get("OCRKeyTerms", "")
        merged["_Score"] = "100"
        merged["_SourceZip"] = "Messages HTML export media folder, not Google Takeout ZIP"
        merged["_PdfRel"] = copy_media(merged.get("HtmlMediaFilePath"), merged.get("CanonicalEventId", "CE-102"), "FILE_5531")
        pdf_cards.append(merged)

    enriched_by_id = {r.get("CanonicalEventId"): r for r in enriched}
    all_phone_artifacts = []
    for row in unique_events:
        event_id = row.get("CanonicalEventId", "")
        if not event_id.startswith("CE-"):
            continue
        if "FILE_5531" in " ".join(row.values()):
            continue
        if event_id in enriched_by_id:
            merged = dict(row)
            merged.update(enriched_by_id[event_id])
            if not merged.get("ConversationContact"):
                merged["ConversationContact"] = "Mom"
            all_phone_artifacts.append(merged)
        else:
            all_phone_artifacts.append(enrich_phone_only_row(row, device_rows))

    google_activity = load_relevant_google_activity()
    all_timeline_rows = sorted(all_phone_artifacts + pdf_cards, key=event_dt)
    sessions = sessionize(all_phone_artifacts, 30)

    total = len(enriched)
    device_total = len(device_rows)
    valid_photo_timing_rows = sum(1 for r in enriched if r.get("GooglePhotosTimeEastern"))
    strong = sum(1 for r in enriched if r.get("MatchClassification", "").startswith("Strong"))
    zero_one = sum(1 for r in enriched if int_or_none(r.get("GooglePhotosMinusCaptureSeconds")) in (0, 1))
    sent_30 = sum(1 for r in all_phone_artifacts if (int_or_none(r.get("CaptureToTextSeconds") or r.get("ElapsedSeconds")) is not None and 0 <= int_or_none(r.get("CaptureToTextSeconds") or r.get("ElapsedSeconds")) <= 30))
    sensitive = [r for r in all_phone_artifacts if r.get("_CleanCategory") or r.get("_CleanTerms")]
    sensitive_zero_one = [r for r in sensitive if int_or_none(r.get("GooglePhotosMinusCaptureSeconds")) in (0, 1)]
    dim_matches = sum(1 for r in all_phone_artifacts if "1170x2532" in (r.get("PhoneImageDimensions") or r.get("Dimensions") or "") and "216" in (r.get("PhoneImageDPI") or r.get("DPI") or ""))

    cat_counter = Counter()
    for row in sensitive:
        for part in re.split(r";|,", row.get("_CleanCategory", "") + ";" + row.get("_CleanTerms", "")):
            part = part.strip()
            if part:
                cat_counter[part] += 1

    gps_rows = [r for r in all_phone_artifacts if r.get("_GPSLatitude") and r.get("_GPSLongitude")]
    if gps_rows:
        gps_table_rows = []
        for r in sorted(gps_rows, key=event_sort_key):
            gps_table_rows.append(f"""
            <tr>
              <td><a href="#{esc(r.get('CanonicalEventId'))}">{esc(r.get('CanonicalEventId'))}</a></td>
              <td>{esc(r.get('Exhibit') or r.get('PrimaryExhibitNumber') or r.get('GooglePhotosTitle'))}</td>
              <td>{esc(r.get('_GPSFilename') or r.get('GooglePhotosTitle') or r.get('PhoneHtmlMediaName'))}</td>
              <td class="time">{esc(r.get('CaptureTimeEastern') or r.get('ScreenshotFilenameTimestamp'))}</td>
              <td class="time">{esc(r.get('GooglePhotosTimeEastern'))}</td>
              <td>{esc(r.get('_GPSLatitude'))}</td>
              <td>{esc(r.get('_GPSLongitude'))}</td>
              <td>{esc(r.get('_GPSDistanceMeters'))} m</td>
              <td>{esc(r.get('_GPSMetadataSource'))}</td>
              <td>{esc(r.get('_GPSSourcePath'))}</td>
            </tr>
            """)
        gps_summary_html = f"""
        <section id="gps-summary">
          <h2>Google Photos GPS Metadata Summary</h2>
          <div class="plain">
            <p><span class="label">GPS display rule:</span> GPS metadata is displayed only where Google Photos/Takeout metadata or EXIF data contains usable latitude/longitude. Many screenshots do not contain GPS metadata. Absence of a GPS field on a card means no usable GPS metadata was found for that matched item.</p>
            <p><span class="label">Evidence boundary:</span> GPS metadata is device/account location context only. It does not by itself identify the physical user.</p>
          </div>
          <table>
            <thead><tr><th>CE ID</th><th>EX ID / match</th><th>Filename</th><th>Capture time</th><th>Google Photos backup/sync time</th><th>Latitude</th><th>Longitude</th><th>Distance from 6275 S. Williamson reference coordinate</th><th>Metadata source</th><th>Source path</th></tr></thead>
            <tbody>{''.join(gps_table_rows)}</tbody>
          </table>
        </section>
        """
    else:
        gps_summary_html = """
        <section id="gps-summary">
          <h2>Google Photos GPS Metadata Summary</h2>
          <div class="plain notice">
            <p><span class="label">GPS search result:</span> No usable per-item GPS metadata was found for the matched screenshot/Google Photos items in the reviewed Takeout sources. Prior GPS-bearing Google Photos items should be kept only in the separate location-context section if independently identified.</p>
            <p><span class="label">Evidence boundary:</span> GPS metadata is device/account location context only. It does not by itself identify the physical user.</p>
          </div>
        </section>
        """

    highlights = sorted(sensitive, key=lambda r: (-category_score(r), event_sort_key(r)))[:24]
    highlight_ids = {r.get("CanonicalEventId") for r in highlights}
    chronological_highlights = sorted(highlights, key=event_sort_key)

    session_html = []
    for i, sess in enumerate(sessions, 1):
        start = event_sort_key(sess[0])
        end = event_sort_key(sess[-1])
        lookback_start = start - timedelta(hours=2)
        cats = Counter()
        session_text = ""
        for r in sess:
            text = (r.get("_CleanCategory", "") + ";" + r.get("_CleanTerms", "")).lower()
            session_text += " " + text + " " + (r.get("VisualDescription", "").lower())
            for name in ("gmail", "drive", "irs/ein", "bank", "navy federal", "helo", "google business", "business record", "financial statement", "venmo", "jonathan", "ariana"):
                if name in text or name.replace("/", " ") in text:
                    cats[name] += 1
        subject_terms = ("helo", "ein", "navy federal", "bank", "statement", "jonathan", "ariana", "gavin", "elijah", "venmo")
        related_activity = []
        for g in google_activity:
            g_text = g.get("_Short", "").lower()
            in_lookback = lookback_start <= g["_DT"] <= end
            is_apr25_main_business_session = start.date() == datetime(2024, 4, 25).date() and start.hour <= 13
            earlier_same_subject = (
                is_apr25_main_business_session
                and
                start - timedelta(hours=72) <= g["_DT"] <= end
                and any(term in g_text and term in session_text for term in subject_terms)
            )
            if in_lookback or earlier_same_subject:
                related_activity.append(g)
        links = " ".join(f'<a href="#{esc(r.get("CanonicalEventId"))}">{esc(r.get("CanonicalEventId"))}</a>' for r in sess)
        activity_items = []
        for g in related_activity[:8]:
            note = f'<span class="neutral-note">{esc(g.get("_NeutralNote"))}</span>' if g.get("_NeutralNote") else ""
            cls = "neutral" if g.get("_NeutralNote") else ""
            activity_items.append(
                f'<li class="{cls}"><span class="time">{esc(g["_DT"].strftime("%Y-%m-%d %I:%M:%S %p"))}</span> '
                f'<span class="svc">{esc(g.get("Google Service", ""))}</span> {syntax_description(g.get("_Short", ""))} {note}</li>'
            )
        activity_bits = "".join(activity_items) or "<li>No relevant parsed Google activity row found in the two-hour lookback window for this session.</li>"
        session_html.append(f"""
        <section class="session">
          <h3>Session {i}: {start.strftime('%Y-%m-%d %I:%M:%S %p')} to {end.strftime('%Y-%m-%d %I:%M:%S %p')}</h3>
          <p><span class="codekey">events</span> <span class="num">{len(sess)}</span> <span class="codekey">visible subjects</span> {esc(', '.join([k for k, _ in cats.most_common(8)]) or 'not tagged')}</p>
          <details open><summary>Related Google activity rows</summary><ul>{activity_bits}</ul></details>
          <p class="session-links">{links}</p>
        </section>
        """)

    phone_timeline_rows = []
    for row in all_timeline_rows:
        dt = event_dt(row)
        if not dt:
            continue
        phone_timeline_rows.append(f"""
        <tr>
          <td class="time">{esc(dt.strftime('%Y-%m-%d'))}<br><b>{esc(dt.strftime('%I:%M:%S %p'))}</b></td>
          <td><a href="#{esc(row.get('CanonicalEventId'))}">{esc(row.get('CanonicalEventId'))}</a></td>
          <td>{esc(row.get('EventType') or 'Screenshot backup/transmission')}</td>
          <td>{esc(trunc(row.get('_CleanCategory') or row.get('VisualDescription'), 150))}</td>
          <td>{esc(row.get('GooglePhotosMinusCaptureSeconds') or '')}</td>
          <td>{esc(row.get('CaptureToTextSeconds') or row.get('ElapsedSeconds') or '')}</td>
        </tr>
        """)

    google_activity_table_rows = []
    for g in google_activity:
        neutral = g.get("_NeutralNote", "")
        google_activity_table_rows.append(f"""
        <tr class="{'neutral-row' if neutral else ''}">
          <td class="time">{esc(g['_DT'].strftime('%Y-%m-%d'))}<br><b>{esc(g['_DT'].strftime('%I:%M:%S %p'))}</b></td>
          <td>{esc(g.get('Google Service'))}</td>
          <td>{syntax_label(g.get('Event Type'))}</td>
          <td>{syntax_description(g.get('_Term') or g.get('Description'))}{('<div class="neutral-note">' + esc(neutral) + '</div>') if neutral else ''}</td>
          <td>{esc(g.get('Source File'))}</td>
        </tr>
        """)

    combined_events = []
    for g in google_activity:
        combined_events.append({
            "dt": g["_DT"],
            "kind": "Google activity",
            "label": f"{g.get('Google Service')} {g.get('Event Type')}",
            "description": g.get("_Term") or trunc(g.get("Description"), 180),
            "anchor": "",
            "source": g.get("Source File", ""),
            "neutral": g.get("_NeutralNote", ""),
        })
    for row in all_timeline_rows:
        dt = event_dt(row)
        if dt == datetime.max:
            continue
        combined_events.append({
            "dt": dt,
            "kind": "Phone artifact",
            "label": row.get("EventType") or "Screenshot/PDF sequence",
            "description": row.get("_CleanCategory") or trunc(row.get("VisualDescription"), 180),
            "anchor": row.get("CanonicalEventId", ""),
            "source": row.get("PhoneHtmlMediaPath") or row.get("HtmlMediaFilePath") or row.get("GooglePhotosMetadataPath") or "",
            "neutral": "",
        })
    combined_events.sort(key=lambda x: x["dt"])
    combined_timeline_rows = []
    for ev in combined_events:
        ref = f'<a href="#{esc(ev["anchor"])}">{esc(ev["anchor"])}</a>' if ev["anchor"] else '<span class="muted">Google log</span>'
        row_class = "google-row" if ev["kind"] == "Google activity" else "phone-row"
        if ev.get("neutral"):
            row_class += " neutral-row"
        combined_timeline_rows.append(f"""
        <tr class="{row_class}">
          <td class="time">{esc(ev['dt'].strftime('%Y-%m-%d'))}<br><b>{esc(ev['dt'].strftime('%I:%M:%S %p'))}</b></td>
          <td>{ref}</td>
          <td>{esc(ev['kind'])}</td>
          <td>{syntax_label(ev['label'])}</td>
          <td>{syntax_description(ev['description'])}{('<div class="neutral-note">' + esc(ev.get('neutral')) + '</div>') if ev.get('neutral') else ''}</td>
          <td>{esc(ev['source'])}</td>
        </tr>
        """)

    top_cards = "\n".join(card(r, i + 1, True) for i, r in enumerate(chronological_highlights))
    full_cards = "\n".join(card(r, i + 1, r.get("CanonicalEventId") in highlight_ids) for i, r in enumerate(sorted(all_phone_artifacts, key=event_sort_key)))
    pdf_html = "\n".join(card(r, None, True) for r in pdf_cards)
    ce018_rows = [r for r in enriched if r.get("CanonicalEventId") == "CE-018"]
    key_ein_sequence_html = "\n".join(
        card(r, i + 1, True)
        for i, r in enumerate(pdf_cards + ce018_rows)
    )
    location_html = build_location_summary_html()

    css = """
    :root { color-scheme: dark; --bg:#101214; --panel:#171a1f; --panel2:#1e232b; --line:#303744; --text:#e9edf1; --muted:#9ba7b3; --blue:#79b8ff; --green:#9ece6a; --purple:#bb9af7; --orange:#ffb86c; --red:#ff6b7a; --cyan:#73daca; --yellow:#ffd866; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family: "Segoe UI", system-ui, sans-serif; line-height:1.45; }
    a { color:var(--blue); text-decoration:none; }
    a:hover { text-decoration:underline; }
    header { padding:34px clamp(18px, 4vw, 52px); background:#0b0d10; border-bottom:1px solid var(--line); }
    .topnav { position:sticky; top:0; z-index:5; display:flex; flex-wrap:wrap; gap:8px; padding:10px clamp(14px, 3vw, 42px); background:#11161d; border-bottom:1px solid var(--line); }
    .topnav a { padding:7px 10px; border:1px solid #303744; border-radius:6px; background:#1b212b; color:var(--cyan); font-weight:700; font-size:13px; }
    h1 { margin:0 0 10px; font-size:clamp(28px, 4vw, 48px); letter-spacing:0; }
    h2 { margin:40px 0 14px; font-size:clamp(22px, 2.4vw, 32px); }
    h3 { margin:0 0 8px; font-size:20px; }
    main { padding:0 clamp(14px, 3vw, 42px) 60px; max-width:1500px; margin:0 auto; }
    .subtitle { color:var(--muted); font-size:18px; max-width:1050px; }
    .banner { margin-top:20px; padding:18px 20px; background:linear-gradient(90deg, rgba(121,184,255,.13), rgba(187,154,247,.1)); border:1px solid var(--line); border-left:5px solid var(--blue); border-radius:8px; max-width:1180px; }
    .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:24px 0; }
    .stat { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; }
    .stat .n { display:block; font-size:30px; color:var(--green); font-weight:700; }
    .stat .l { color:var(--muted); font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
    .plain { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px 20px; }
    .plain li { margin:8px 0; }
    .codekey { color:var(--purple); font-family:Consolas, monospace; font-weight:700; }
    .num { color:var(--orange); font-family:Consolas, monospace; font-weight:700; }
    .good { color:var(--green); font-weight:700; }
    .warn { color:var(--yellow); font-weight:700; }
    .bad { color:var(--red); font-weight:700; }
    .label { color:var(--cyan); font-weight:800; }
    .action-gmail { color:#73daca; font-weight:700; }
    .action-search { color:#bb9af7; font-weight:700; }
    .action-screenshot { color:#ffb86c; font-weight:700; }
    .action-pdf { color:#ff6b7a; font-weight:700; }
    .desc-term { color:#ffd866; font-weight:700; }
    .desc-sensitive { color:#ff9e64; font-weight:700; }
    .desc-account { color:#9ece6a; font-weight:700; }
    .neutral-note { display:block; margin-top:4px; color:#9ba7b3; font-size:12px; font-style:italic; }
    tr.neutral-row td, li.neutral { opacity:.78; }
    .gpsbox { margin:10px 0; padding:10px 12px; border:1px solid #2a313c; border-left:4px solid var(--cyan); border-radius:6px; background:#151b23; }
    .gpsbox p { margin:4px 0; }
    .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
    .session { background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--purple); border-radius:8px; padding:15px; margin:10px 0; }
    .session-links a { display:inline-block; margin:3px; padding:4px 7px; border-radius:5px; background:#252b35; color:var(--cyan); font-family:Consolas, monospace; }
    table { width:100%; border-collapse:collapse; background:var(--panel); border-radius:8px; overflow:hidden; }
    th,td { border-bottom:1px solid var(--line); padding:10px; vertical-align:top; text-align:left; }
    th { background:#202631; color:var(--cyan); position:sticky; top:0; z-index:1; }
    tr:nth-child(even) td { background:#141820; }
    tr.google-row td { background:#151d2a; }
    tr.phone-row td { background:#171a1f; }
    .time { color:var(--orange); font-family:Consolas, monospace; white-space:nowrap; }
    .svc { color:var(--blue); font-family:Consolas, monospace; font-weight:700; }
    .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px; margin:16px 0; }
    .card.critical { border-left:5px solid var(--red); }
    .card-head { display:flex; justify-content:space-between; gap:16px; border-bottom:1px solid var(--line); padding-bottom:12px; margin-bottom:14px; }
    .ordinal { color:var(--muted); font-family:Consolas, monospace; }
    .score { color:var(--yellow); font-family:Consolas, monospace; white-space:nowrap; }
    .tags { display:flex; flex-wrap:wrap; gap:6px; }
    .chip { display:inline-block; padding:4px 8px; border-radius:999px; background:#262c36; color:var(--muted); font-size:12px; font-weight:700; }
    .chip.cat { color:#ffb86c; }
    .chip.match { color:#9ece6a; }
    .chip.ios { color:#79b8ff; }
    .chip.dim { color:#bb9af7; }
    .card-grid { display:grid; grid-template-columns:minmax(360px, 2fr) minmax(280px, 1fr); gap:18px; align-items:start; }
    .facts { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:8px; }
    .fact { background:var(--panel2); border:1px solid #2a313c; border-radius:6px; padding:8px; min-width:0; }
    .k { display:block; color:var(--purple); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
    .v { display:block; color:var(--text); font-family:Consolas, monospace; overflow-wrap:anywhere; }
    .v.hot { color:var(--green); font-weight:700; }
    .v.muted { color:var(--muted); }
    .media img { width:100%; max-height:560px; object-fit:contain; background:#07080a; border:1px solid var(--line); border-radius:8px; }
    .pdfpreview object { width:100%; height:560px; background:#07080a; border:1px solid var(--line); border-radius:8px; }
    .openfile { display:inline-block; margin-top:8px; font-weight:700; color:var(--cyan); }
    .pdfbox,.noimg { min-height:220px; display:flex; align-items:center; justify-content:center; flex-direction:column; gap:12px; border:1px dashed var(--line); border-radius:8px; background:#0c0f13; color:var(--muted); }
    .pdficon { color:#fff; background:var(--red); padding:14px 18px; border-radius:6px; font-weight:800; letter-spacing:.1em; }
    .explain { margin-top:12px; color:#d6dde5; }
    details { margin-top:10px; }
    summary { cursor:pointer; color:var(--cyan); font-weight:700; }
    .source { margin-top:10px; display:grid; gap:8px; }
    .notice { border-left:5px solid var(--yellow); }
    .print-note { color:var(--muted); font-size:13px; }
    @media (max-width: 900px) {
      .grid2, .card-grid { grid-template-columns:1fr; }
      .card-head { display:block; }
      th, td { font-size:14px; }
      .pdfpreview object { height:420px; }
    }
    """

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Google Photos Backup + iPhone Screenshot/SMS Timing Evidence Packet</title>
  <style>{css}</style>
</head>
<body>
<header>
  <h1>Google Photos Backup + iPhone Screenshot/SMS Timing Evidence Packet</h1>
  <p class="subtitle">Plain-English evidence packet describing what the reviewed records show, what they support, and what still needs native-provider confirmation.</p>
  <div class="banner"><b>Core sequence:</b> recovered iPhone screenshot artifact → near-immediate Google Photos backup/sync for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span> with <span class="codekey">IOS_PHONE</span> origin → same/related item texted or linked in the <span class="codekey">TO: Mom</span> message thread seconds later.</div>
</header>
<nav class="topnav">
  <a href="#investigative-gap">Investigative Gap</a>
  <a href="#phone-account-context">Phone Account Context</a>
  <a href="#bottom-line">Bottom Line</a>
  <a href="#location-context">Location Context</a>
  <a href="#google-activity">Google Activity</a>
  <a href="#timeline">Chronology</a>
  <a href="#ein-sequence">EIN Timing Chain</a>
  <a href="#sessions">Sessions</a>
  <a href="#highlights">Highlights</a>
  <a href="#all-cards">Full Appendix</a>
  <a href="#follow-up">Follow-Up</a>
</nav>
<main>
  <section id="investigative-gap">
    <h2>Supplemental Evidence Addressing Prior Investigative Gap</h2>
    <div class="plain notice">
      <p>Port Orange Police Department previously reviewed recovered screenshots from Elijah's iPhone and stated, in substance, that the investigation lacked evidence showing how the screenshots appeared on the phone or evidence indicating account, email, or database access.</p>
      <p>This supplemental packet addresses that investigative gap by correlating recovered iPhone/message artifacts, screenshot capture timestamps, Google Photos backup/sync records exported through Google Takeout for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>, live-account confirmation by Thomas Hurd that the same matched items were visible in the Google Photos app for that same account, and near-immediate transmission to the <span class="codekey">Mom</span> message thread.</p>
      <p><span class="label">Live-account confirmation:</span> The presence of the same matched items in the live Google Photos app for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>, after discovery through Google Takeout, supports that these were not merely parser artifacts from an export.</p>
      <p>This packet does not ask the reader to accept a legal conclusion. It presents a timing and source-correlation pattern that should be evaluated with native iPhone records, Apple/iCloud records, Google provider records, message databases, and witness statements.</p>
    </div>
    <div class="stats">
      <div class="stat"><span class="n">{device_total}</span><span class="l">recovered phone/message artifacts reviewed</span></div>
      <div class="stat"><span class="n">{sent_30}</span><span class="l">texted/linked within 30 sec</span></div>
      <div class="stat"><span class="n">{valid_photo_timing_rows}</span><span class="l">valid per-item Google Photos backup/sync timing rows</span></div>
      <div class="stat"><span class="n">{len(sensitive_zero_one)}</span><span class="l">sensitive matches with 0-1 sec backup/sync</span></div>
    </div>
    <div class="grid2">
      <div class="plain">
        <h3>What This Supports</h3>
        <p><span class="label">Timing pattern:</span> The records support a fresh capture, backup/sync, and transmission sequence involving sensitive business and financial materials from or concerning the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>.</p>
        <p><span class="label">Evidence significance:</span> The timing pattern is materially different from someone merely discovering old screenshots later. The records support the inference that sensitive Google, Gmail, Google Drive, Google Business, or related business-financial materials were displayed, captured, backed up/synced through Google Photos, and transmitted in the <span class="codekey">Mom</span> thread within seconds.</p>
        <p><span class="label">Strongest example:</span> The <span class="codekey">FILE_5531.pdf</span> / CE-018 EIN sequence is the strongest example because it includes a PDF transmission to <span class="codekey">Mom</span>, a screenshot of the same EIN document approximately 12 seconds later, same-second Google Photos backup/sync, and a later message-thread transmission.</p>
      </div>
      <div class="plain">
        <h3>Live-Account Confirmation Note</h3>
        <p>After the Google Takeout export revealed the matched Google Photos items, Thomas Hurd manually checked the Google Photos app while logged into the Google account associated with <span class="codekey">keeganhurd@gmail.com</span> and confirmed that the same items were visible in that account.</p>
        <p>This live-account observation should be independently verified by provider records, investigator review, or other native Google account records if needed.</p>
      </div>
    </div>
    <div class="grid2">
      <div class="plain notice">
        <h3>What This Does Not Prove Alone</h3>
        <p><span class="label">Evidence boundary:</span> This packet does not by itself identify the physical user or prove legal intent. It should be treated as a structured timing-and-correlation packet that supports further investigation, provider-record requests, and sworn questioning regarding source, access, possession, capture, backup/sync, and transmission.</p>
        <p><span class="label">Investigative significance:</span> The evidentiary significance is that the records are materially inconsistent with a simple "old screenshots found later" explanation unless native/provider records show a different source path.</p>
      </div>
      <div class="plain">
        <h3>Recommended Investigative Follow-Up</h3>
        <ul>
          <li>Who physically possessed the iPhone during the April 25, 2024 12:23 PM-2:11 PM session?</li>
          <li>Was the device logged into, syncing with, or accessing the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>?</li>
          <li>What Apple/iCloud account was active on the device at the time?</li>
          <li>What Google account was active in Google Photos, Gmail, Drive, Safari, Chrome, or other Google apps?</li>
          <li>Who was <span class="codekey">Mom</span> in the message thread receiving the screenshots/files?</li>
          <li>Were the screenshots captured live, or were they screenshots of pre-existing screenshots?</li>
          <li>Do native iPhone databases show creation time, attachment GUIDs, deletion status, sender/recipient handle, and message-thread identity?</li>
          <li>Do Google server logs show access, IP address, device/user-agent, session, Gmail search, Drive access, Google Photos upload, Google Business access, or account security activity?</li>
          <li>Do school attendance records, campus records, bus records, Apple/iCloud records, Google provider records, or account/device logs confirm that Elijah was at school while the iPhone or Google Photos activity was located near the 6275 S. Williamson GPS cluster during the April 25, 2024 12:23 PM-2:11 PM session?</li>
          <li>Did Robin Hurd later possess, describe, transmit, rely on, or provide these materials to her attorney, the court, the Department of Revenue, or the Social Investigator?</li>
          <li>Did any person use Elijah's device, account, passcode, iCloud account, Google account, Google Photos app, Gmail app, Drive app, browser, or messages to access, capture, preserve, forward, or transmit these materials?</li>
          <li>Do the message records show whether any attachments were deleted, forwarded, edited, saved, exported, or synced after transmission?</li>
        </ul>
      </div>
    </div>
  </section>

  <section id="phone-account-context">
    <h2>Phone Account Context Reported by Thomas Hurd</h2>
    <div class="plain">
      <p><span class="label">Reported account setup:</span> Thomas Hurd reports that Elijah&apos;s iPhone normally used the Google account <span class="codekey">elijahbhurd@gmail.com</span>, but the Google account <span class="codekey">keeganhurd@gmail.com</span> had also been added to the phone because Thomas previously created or used a YouTube-related account/profile for Elijah under Thomas&apos;s Google account when Elijah was under the age threshold for his own unrestricted YouTube access.</p>
      <p><span class="label">Reported later account removal:</span> Thomas reports that, after the April 2024 incident, Elijah removed <span class="codekey">keeganhurd@gmail.com</span> from the iPhone to prevent further access. Therefore, the account state of the iPhone when later reviewed may not reflect the account state of the phone during the April 2024 screenshot/backup/transmission window.</p>
      <p><span class="label">Verification needed:</span> This should be verified through native iPhone records, Apple/iCloud records, Google account records, Google Photos records, and any available device/account session logs.</p>
      <p><span class="label">Key forensic issue:</span> The key forensic issue is not merely whether screenshots existed on the phone at the time of later review. The key issue is whether, during the April 2024 window, the phone was logged into, syncing with, or able to access the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>, and whether the records show fresh capture, Google Photos backup/sync, and near-immediate transmission to the <span class="codekey">Mom</span> thread.</p>
    </div>
  </section>

  <section id="bottom-line">
    <h2>One-Page Bottom Line</h2>
    <div class="plain">
      <p><span class="label">What the records strongly support:</span> The reviewed records show a repeated April 25-26, 2024 sequence in which screenshots of Gmail, Google Business/Profile, Google Drive/EIN, bank, and business-financing material were captured on an iOS-sized phone image, backed up/synced through Google Photos for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span> almost immediately, and then transmitted in the "Mom" message thread seconds later.</p>
      <p><span class="label">Why this matters:</span> This pattern is materially different from someone merely later finding old screenshots. The timing supports fresh capture, Google Photos backup/sync for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>, and near-immediate message transmission.</p>
      <p><span class="label">Reliability framing:</span> For a civil/family-court reliability question, the most consistent record-supported narrative is that the phone was able to access the Google account material, the sensitive material was captured as screenshots or a PDF attachment, those items backed up/synced through Google Photos for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>, and the same material was sent in the "Mom" thread within seconds. This is presented as an evidence-based inference, not a legal conclusion.</p>
      <p><span class="label">Evidence boundary:</span> The records support the access/capture/transmission sequence. The records do not, standing alone, prove the physical user's identity or legal intent. Native iPhone, Apple/iCloud, Google server-side, and provider records should be used to confirm the actor, account/session state, deletion status, and location.</p>
    </div>
    <div class="stats">
      <div class="stat"><span class="n">{device_total}</span><span class="l">recovered phone/message artifacts reviewed</span></div>
      <div class="stat"><span class="n">{total}</span><span class="l">Google Photos comparison rows</span></div>
      <div class="stat"><span class="n">{valid_photo_timing_rows}</span><span class="l">valid per-item backup timing rows</span></div>
      <div class="stat"><span class="n">{strong}</span><span class="l">strong timing/visual matches</span></div>
      <div class="stat"><span class="n">{zero_one}</span><span class="l">backed up 0-1 sec from capture</span></div>
      <div class="stat"><span class="n">{sent_30}</span><span class="l">texted/linked within 30 sec</span></div>
      <div class="stat"><span class="n">{len(sensitive_zero_one)}</span><span class="l">sensitive matches with 0-1 sec backup</span></div>
      <div class="stat"><span class="n">{dim_matches}</span><span class="l">1170x2532 / 216 DPI image records</span></div>
    </div>
    <div class="plain notice">
      <p><b>Why the Google Photos count is lower than the phone/message count:</b> The phone-side review contains <span class="num">{device_total}</span> recovered artifacts. The Google Photos comparison contains <span class="num">{total}</span> rows because only some phone artifacts could be paired to an exported Google Photos item. That gap does not mean the other artifacts are false; it means this packet cannot claim a Google Photos backup match for every phone artifact.</p>
      <p>Possible explanations include screenshots deleted before backup, backup settings or connection state, Google Photos export coverage, non-photo items such as <span class="codekey">FILE_5531.pdf</span>, and events where the phone artifact exists but no reliable matching Google Photos row was found. The stronger claim is limited to the rows with a valid Google Photos timing match.</p>
    </div>
  </section>

  {location_html}

  <section id="google-activity">
    <h2>Google Activity Correlation</h2>
    <div class="plain">
      <p><span class="label">Account activity boundary:</span> Google Takeout My Activity records include Gmail/search activity in the same evidence window. These rows do not identify the physical user by themselves, but some rows show account-side searches that line up with the recovered phone artifacts and visible screenshot subjects.</p>
      <p><span class="label">Caution:</span> Because this was Thomas Hurd&apos;s Google account, some Google Activity rows may reflect authorized activity by Thomas. This packet treats account activity as probative only when timing, subject matter, and nearby phone/message artifacts support correlation.</p>
      <p><span class="label">Most important rows:</span> Gmail searched <span class="codekey">elijah hurd</span> at 11:08:01 AM on April 19, shortly before the first recovered April 19 phone artifacts; Gmail searched <span class="codekey">helo payment services ein</span> at 2:13:41 PM on April 23, matching the EIN subject later transmitted and screenshotted on April 25; Google Search shows a <span class="codekey">docs.google.com</span> presentation URL at 11:32:19 AM on April 25, before the main 12:23 PM to 2:11 PM capture session; Gmail searched <span class="codekey">Jonathan</span>, an Airbnb reply address, and <span class="codekey">Ariana</span> during the April 26 morning screenshot sequence.</p>
      <p><span class="label">Limit:</span> The <span class="codekey">helo payment services ein</span> Gmail search is earlier same-subject account activity, not a minute-by-minute precursor to the April 25 PDF transmission. The tightest timing remains the FILE_5531.pdf transmission followed by CE-018 screenshot, zero-second Google Photos backup/sync, and message-thread transmission.</p>
    </div>
    <details open><summary>Google activity rows used in this packet</summary>
      <table>
        <thead><tr><th>Date/time</th><th>Service</th><th>Type</th><th>Search/log item</th><th>Source file</th></tr></thead>
        <tbody>{''.join(google_activity_table_rows)}</tbody>
      </table>
    </details>
  </section>

  <section id="timeline">
    <h2>Chronological Timeline</h2>
    <div class="plain">
      <p>This timeline merges Google Takeout activity rows with the recovered phone/PDF/screenshot artifacts. Blue-toned rows are Google logs; dark rows are recovered phone/message artifacts. It is arranged by when each record says the event occurred.</p>
    </div>
    <table>
      <thead><tr><th>Date/time</th><th>Event</th><th>Record type</th><th>Action</th><th>Description</th><th>Source</th></tr></thead>
      <tbody>{''.join(combined_timeline_rows)}</tbody>
    </table>
  </section>

  <section id="ein-sequence">
    <h2>FILE_5531.pdf / CE-018 Timing Chain</h2>
    <div class="plain">
      <p><span class="label">Timing chain:</span> This is the cleanest timing example because the message export contains a PDF identified as an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC, followed approximately 12 seconds later by a screenshot of the same EIN letter, with Google Photos backup/sync at the same second as the screenshot capture, and message transmission approximately 12 seconds after capture.</p>
      <p><span class="label">Careful limitation:</span> This strongly supports a fresh access/display/capture/backup/transmission sequence, but native iPhone, Apple/iCloud, and Google provider records should confirm the exact source path of the PDF and screenshot.</p>
    </div>
    <h3>FILE_5531.pdf / CE-018 Timing Chain</h3>
    <table>
      <thead><tr><th>Event</th><th>Time</th><th>Delta</th></tr></thead>
      <tbody>
        <tr><td>{syntax_description('FILE_5531.pdf appears in message export / "Mom" sequence')}</td><td class="time">12:54:20 PM</td><td>Start</td></tr>
        <tr><td>{syntax_description('CE-018 screenshot captures same EIN letter')}</td><td class="time">12:54:32 PM</td><td>+12 seconds after PDF</td></tr>
        <tr><td>{syntax_description('Google Photos backup/sync for matched CE-018 item')}</td><td class="time">12:54:32 PM</td><td>Same second as screenshot capture</td></tr>
        <tr><td>{syntax_description('CE-018 screenshot texted/linked to "Mom"')}</td><td class="time">12:54:44 PM</td><td>+12 seconds after screenshot / +24 seconds after PDF</td></tr>
      </tbody>
    </table>
    {key_ein_sequence_html}
    <div class="plain notice">
      <h3>Reported Statements and Timing Correlation</h3>
      <p><span class="label">Reported POPD statement:</span> Thomas reports that, in the police investigation, Respondent/Mother did not claim Elijah created or transmitted the screenshots. Thomas further reports that Respondent/Mother described finding screenshots or financial materials and also described taking screenshots and providing materials to her attorney. The exact wording should be verified against the POPD report and any Axon/audio/video recording of the interview.</p>
      <p><span class="label">Timing correlation:</span> This matters because the timing evidence should be evaluated against the reported explanation. If the materials were merely "found" later, investigators should determine why the records show repeated screenshot capture, Google Photos backup/sync for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span>, and near-immediate transmission to the <span class="codekey">Mom</span> message thread within seconds.</p>
      <p><span class="label">Investigative significance:</span> If Respondent/Mother contends she took screenshots of already-existing screenshots, investigators should compare that explanation against the screenshot capture times, Google Photos backup/sync timing, message attachment timing, native iPhone records, and Google provider records.</p>
      <p><span class="label">Verification needed:</span> The Axon recording, native iPhone databases, Apple/iCloud records, and Google provider records should be reviewed before attributing physical-device use to any person as a final conclusion.</p>
    </div>
    <div class="plain">
      <h3>Record-Supported Narrative</h3>
      <p><span class="label">Narrative supported by records:</span> The narrative that best fits the reviewed records is: during the April 25 session, a phone with iOS-sized screenshot artifacts accessed or displayed Google account/business material; screenshots and a PDF attachment were captured or transmitted; matching or related items appeared in the "Mom" message thread within seconds; and many matched screenshots backed up/synced through Google Photos for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span> almost immediately. The PDF is especially important because it is an actual transmitted business/IRS document, followed seconds later by a screenshot of the same EIN-letter subject matter.</p>
      <p><span class="label">Evidence boundary:</span> This supports the inference that the person who located the material was involved in the capture/transmission sequence. It does not, standing alone, identify the physical user beyond all possible doubt. The actor identity should be tested against native iPhone records, school/custody/location records, Apple/iCloud records, Google provider logs, and the complete recorded statement/interview.</p>
    </div>
    <div class="plain notice">
      <h3>Alternative Explanations to Test</h3>
      <ul>
        <li><b>Old screenshots already existed:</b> Weakened by the seconds-apart capture filename, Google Photos backup/sync, and message timing. Native Photos database records should confirm creation/import/deletion times.</li>
        <li><b>Elijah captured and sent them:</b> Test against school attendance, campus phone policy, device location, Apple Screen Time, possession/custody timeline, and whether Elijah had practical ability or motive to navigate Gmail/Drive/business records.</li>
        <li><b>Thomas captured them:</b> Test against Thomas&apos;s own device type, location, custody/possession of Elijah&apos;s phone, and the repeated 1170x2532 / 216 DPI phone-image pattern matching the Elijah iPhone reference rather than Thomas&apos;s stated iPhone 8.</li>
        <li><b>Automatic sync caused confusion:</b> Google Photos backup/sync can explain why items appeared in the Google account, but it does not by itself explain the seconds-later message transmissions to "Mom" or the separate FILE_5531.pdf attachment.</li>
        <li><b>Someone else used the phone:</b> Possible in the abstract; test against household access, custody schedule, location records, the "Mom" thread recipient, the reported statements, and native message/attachment sender-recipient metadata.</li>
      </ul>
    </div>
  </section>

  <section id="sessions">
    <h2>Capture / Transmission Sessions</h2>
    <div class="plain">
      <p><span class="label">Session grouping:</span> These sessions are grouped chronologically using the recovered phone/message artifacts. The grouping is descriptive only; it does not identify the physical user. April 19 is the first recovered phone-evidence session; the April 25 noon-to-2 PM run is the main business/financial document session.</p>
    </div>
    {''.join(session_html)}
  </section>

  <section id="highlights">
    <h2>Most Probative Chronological Highlights</h2>
    <p class="print-note">These are not ranked by legal conclusion. They are selected because the visible content is sensitive and the timing chain is easy to explain.</p>
    {top_cards}
  </section>

  <section id="all-cards">
    <h2>All Recovered Phone Artifact Cards</h2>
    <p class="print-note">This appendix preserves the broader dataset so the packet does not cherry-pick. Cards are chronological. Google Photos backup/sync fields appear only where a valid Google Photos match was recovered.</p>
    <details><summary>Show all recovered phone artifact cards</summary>
      {full_cards}
    </details>
  </section>

  <section id="phone-artifact-appendix">
    <h2>Phone Artifact Timing Appendix</h2>
    <details><summary>Show phone artifact timing table</summary>
      <table>
        <thead><tr><th>Date/time</th><th>Event</th><th>Type</th><th>Visible subject</th><th>Backup delta sec</th><th>Send delta sec</th></tr></thead>
        <tbody>{''.join(phone_timeline_rows)}</tbody>
      </table>
    </details>
  </section>

  <section id="follow-up">
    <h2>Provider Records to Request</h2>
    <div class="plain">
      <ul>
        <li><b>Thomas-provided Google export:</b> Thomas Hurd can provide the Google Takeout ZIP files for the Google account associated with <span class="codekey">keeganhurd@gmail.com</span> for independent review.</li>
        <li><b>Google account/session records:</b> Google account session/device logs for <span class="codekey">keeganhurd@gmail.com</span>, IP address, user-agent, device identifiers, session cookies or account session records where available.</li>
        <li><b>Google Photos:</b> Google Photos upload/sync logs and metadata confirming upload device, account, timestamp, and GPS where available.</li>
        <li><b>Gmail:</b> Gmail search/access logs for April 19-26, 2024.</li>
        <li><b>Google Drive:</b> Google Drive access/download/open/preview logs, including records for PDFs, Docs, Sheets, Slides, and any <span class="codekey">FILE_5531.pdf</span> / EIN-related item.</li>
        <li><b>Google Business/Profile:</b> Google Business Profile / Google Business access logs and account activity.</li>
        <li><b>Apple/iCloud:</b> Apple/iCloud records for the iPhone during April 19-26, 2024, including Photos creation/import/deletion records, iMessage/SMS attachment metadata, iCloud Photos sync status, device location records, and relevant account/device logs.</li>
        <li><b>Native iPhone extraction:</b> <span class="codekey">sms.db</span>, attachment GUIDs, handle tables, deletion status, Photos database, local file timestamps, and records showing whether <span class="codekey">keeganhurd@gmail.com</span> was configured on the iPhone during the April 2024 window.</li>
        <li><b>School records:</b> School attendance/campus records showing whether Elijah was present at school on April 25, 2024, and any school policy/records confirming that student phones were not permitted on campus or were required to remain off campus.</li>
        <li><b>Carrier/provider:</b> records sufficient to authenticate the recipient number and message timing if available.</li>
      </ul>
    </div>
  </section>
</main>
</body>
</html>
"""

    out = PACKET_DIR / "index_chronological_story.html"
    out.write_text(html_doc, encoding="utf-8")

    example_lines = []
    for ex in gps_summary["gps_bearing_examples"][:10]:
        example_lines.append(
            f"- {ex.get('Filename', '')}: {ex.get('Latitude')}, {ex.get('Longitude')} "
            f"source={ex.get('MetadataSource', '')} path={ex.get('SourcePath', '')}"
        )
    if not example_lines:
        example_lines.append("- No GPS-bearing Google Photos sidecar examples were found during this scan.")

    gps_debug = f"""GPS Metadata Search Summary

Folders searched:
{chr(10).join('- ' + str(folder) for folder in gps_summary['folders_searched'])}

JSON sidecars scanned: {gps_summary['json_sidecars_scanned']}
Images indexed by filename: {gps_summary['images_indexed']}
Images scanned for EXIF GPS on matched candidates: {gps_summary['images_scanned_for_exif']}
Matched Google Photos/phone items checked: {gps_summary['matched_items_checked']}
Matched items with usable GPS: {gps_summary['matched_items_with_gps']}
Matched items without usable GPS: {gps_summary['matched_items_without_gps']}

Examples of GPS-bearing files found:
{chr(10).join(example_lines)}

Why GPS may not appear on a matched screenshot item:
- Many screenshots do not contain GPS EXIF metadata.
- Google Photos sidecar JSON files may omit geoData and geoDataExif for screenshots.
- Some phone artifacts were recovered from Messages/HTML exports rather than from Google Photos media exports.
- Some matches depend on timing/visual matching where the sidecar filename does not exactly match the phone artifact filename.
- Google Takeout export coverage can vary by product, file type, and metadata availability.

Display rule used in the HTML:
- If usable latitude/longitude was found for a matched item, the evidence card displays it.
- If usable latitude/longitude was not found, the evidence card omits the GPS field to avoid repetitive clutter.
- GPS metadata is device/account location context only. It does not by itself identify the physical user.
"""
    (PACKET_DIR / "gps_metadata_search_summary.txt").write_text(gps_debug, encoding="utf-8")

    manifest = {
        "created_output": str(out),
        "media_dir": str(MEDIA_DIR),
        "google_photos_correlation_rows": total,
        "strong_matches": strong,
        "zero_or_one_second_backups": zero_one,
        "sent_within_30_seconds": sent_30,
        "sensitive_zero_or_one_second_backups": len(sensitive_zero_one),
        "device_dimension_matches": dim_matches,
        "gps_metadata": {
            "json_sidecars_scanned": gps_summary["json_sidecars_scanned"],
            "images_indexed": gps_summary["images_indexed"],
            "images_scanned_for_exif": gps_summary["images_scanned_for_exif"],
            "matched_items_checked": gps_summary["matched_items_checked"],
            "matched_items_with_gps": gps_summary["matched_items_with_gps"],
            "matched_items_without_gps": gps_summary["matched_items_without_gps"],
        },
        "top_categories": cat_counter.most_common(20),
    }
    (PACKET_DIR / "build_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
