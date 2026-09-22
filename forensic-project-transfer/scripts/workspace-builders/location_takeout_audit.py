import csv
import datetime as dt
import json
import math
import re
from pathlib import Path


ROOT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
TAKEOUT = ROOT / "Takeout"
OUT = ROOT / "_forensic_outputs"
SOURCE_MAP = OUT / "current_takeout_zips_source_map.csv"

START = dt.datetime(2024, 4, 19, 0, 0, 0)
END = dt.datetime(2024, 4, 26, 23, 59, 59)

# User-supplied address for local comparison. Coordinates must be confirmed
# independently; this script does not geocode or use network calls.
TARGET_ADDRESS = "6275 S Williamson Blvd, Port Orange FL 32128"
KNOWN_REFERENCE_POINTS = {
    "Observed_PalmVista_like_cluster_from_metadata": (29.0640, -81.0252),
}

ADDRESS_TERMS = [
    "6275 S Williamson", "S Williamson", "Williamson Blvd", "Port Orange",
    "32128", "6275", "Palm Vista", "Florida Crystal", "Sprinkler",
]


def load_source_map():
    out = {}
    if not SOURCE_MAP.exists():
        return out
    with SOURCE_MAP.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            out[row["ExtractedPath"]] = row
    return out


def parse_google_time(value):
    if not value:
        return None
    value = str(value).replace("\u202f", " ").replace("\xa0", " ")
    for fmt in ("%b %d, %Y, %I:%M:%S %p UTC", "%B %d, %Y, %I:%M:%S %p UTC"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def haversine_m(lat1, lon1, lat2, lon2):
    r = 6371000.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def maybe_media_for_metadata(path):
    name = path.name
    suffixes = [
        ".supplemental-metadata.json", ".supplemental-meta.json",
        ".supplemental-metad.json", ".supplemental-metada.json",
        ".supplemental-me.json", ".supplemental-.json", ".supplemental.json",
        ".suppl.json", ".json",
    ]
    for suffix in suffixes:
        if name.endswith(suffix):
            candidate = path.with_name(name[: -len(suffix)])
            if candidate.exists():
                return str(candidate)
    return ""


def scan_google_photos_metadata(source_by_path):
    rows = []
    for path in TAKEOUT.rglob("*.json"):
        if "Google Photos" not in str(path):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        title = data.get("title", path.name)
        photo_time_raw = data.get("photoTakenTime", {}).get("formatted", "")
        creation_time_raw = data.get("creationTime", {}).get("formatted", "")
        photo_time = parse_google_time(photo_time_raw)
        creation_time = parse_google_time(creation_time_raw)
        ts = photo_time or creation_time
        if not ts or not (START <= ts <= END):
            continue
        geo = data.get("geoData", {}) or {}
        geo_exif = data.get("geoDataExif", {}) or {}
        lat = geo.get("latitude") or geo_exif.get("latitude") or 0
        lon = geo.get("longitude") or geo_exif.get("longitude") or 0
        try:
            lat = float(lat)
            lon = float(lon)
        except Exception:
            lat = lon = 0.0
        has_geo = abs(lat) > 0.000001 or abs(lon) > 0.000001
        nearest_name = ""
        nearest_m = ""
        if has_geo:
            distances = [(name, haversine_m(lat, lon, ref[0], ref[1])) for name, ref in KNOWN_REFERENCE_POINTS.items()]
            nearest_name, nearest = min(distances, key=lambda x: x[1])
            nearest_m = round(nearest, 1)
        source = source_by_path.get(str(path), {})
        rows.append({
            "TimestampUTC": ts.isoformat(sep=" ", timespec="seconds"),
            "Title": title,
            "PhotoTakenTime": photo_time_raw,
            "CreationTime": creation_time_raw,
            "Latitude": lat if has_geo else "",
            "Longitude": lon if has_geo else "",
            "HasGeoData": "Yes" if has_geo else "No",
            "NearestReferencePoint": nearest_name,
            "DistanceMetersToReferencePoint": nearest_m,
            "GooglePhotosOrigin": json.dumps(data.get("googlePhotosOrigin", {}), ensure_ascii=False),
            "SourceZipFilename": source.get("SourceZipFilename", ""),
            "EntryPath": source.get("EntryPath", ""),
            "ExtractedPath": str(path),
            "MediaPath": maybe_media_for_metadata(path),
            "Notes": "Coordinates compared only to local known reference points; target address coordinates not geocoded.",
        })
    return sorted(rows, key=lambda r: r["TimestampUTC"])


def scan_text_for_address_terms(source_by_path):
    rows = []
    term_re = re.compile("|".join(re.escape(t) for t in ADDRESS_TERMS), re.I)
    for path in TAKEOUT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".json", ".html", ".htm", ".txt", ".csv", ".xml", ".log"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = term_re.search(text + "\n" + str(path))
        if not m:
            continue
        start = max(0, m.start() - 240)
        end = min(len(text), m.end() + 360)
        source = source_by_path.get(str(path), {})
        rows.append({
            "MatchedTerm": m.group(0),
            "SourceZipFilename": source.get("SourceZipFilename", ""),
            "EntryPath": source.get("EntryPath", ""),
            "ExtractedPath": str(path),
            "Snippet": re.sub(r"\s+", " ", text[start:end]).strip()[:700],
        })
    return rows


def write_csv(path, rows, headers):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    source_by_path = load_source_map()
    photo_rows = scan_google_photos_metadata(source_by_path)
    address_rows = scan_text_for_address_terms(source_by_path)
    geo_rows = [r for r in photo_rows if r["HasGeoData"] == "Yes"]
    ios_rows = [r for r in photo_rows if "IOS_PHONE" in r.get("GooglePhotosOrigin", "")]

    write_csv(
        OUT / "Location_Audit_Google_Photos_April19_26.csv",
        photo_rows,
        ["TimestampUTC", "Title", "PhotoTakenTime", "CreationTime", "Latitude", "Longitude", "HasGeoData",
         "NearestReferencePoint", "DistanceMetersToReferencePoint", "GooglePhotosOrigin", "SourceZipFilename",
         "EntryPath", "ExtractedPath", "MediaPath", "Notes"],
    )
    write_csv(
        OUT / "Location_Audit_Address_Term_Hits.csv",
        address_rows,
        ["MatchedTerm", "SourceZipFilename", "EntryPath", "ExtractedPath", "Snippet"],
    )

    lines = []
    lines.append("# Location Audit - April 19-26, 2024\n\n")
    lines.append(f"Target address raised by user: `{TARGET_ADDRESS}`\n\n")
    lines.append("No network/geocoding was used. This report does not independently convert the target address into coordinates.\n\n")
    lines.append("## Summary\n\n")
    lines.append(f"- Google Photos April 19-26 metadata rows found: {len(photo_rows)}\n")
    lines.append(f"- Rows with nonzero latitude/longitude: {len(geo_rows)}\n")
    lines.append(f"- Rows with Google Photos origin showing IOS_PHONE: {len(ios_rows)}\n")
    lines.append(f"- Address/name text hits: {len(address_rows)}\n\n")
    if geo_rows:
        lines.append("## GPS-bearing Google Photos rows\n\n")
        for row in geo_rows[:80]:
            lines.append(
                f"- {row['TimestampUTC']} UTC | {row['Title']} | lat/lon {row['Latitude']}, {row['Longitude']} | "
                f"source ZIP `{row['SourceZipFilename']}` | {row['GooglePhotosOrigin']}\n"
            )
    else:
        lines.append("## GPS-bearing Google Photos rows\n\nNo nonzero GPS coordinates were recovered in Google Photos metadata for April 19-26 in the extracted set.\n")
    lines.append("\n## Caveat\n\n")
    lines.append("A Google Photos GPS point can show where a photo/video was taken or uploaded from, depending on metadata, but it does not by itself identify who held the device. For actor attribution, compare this with native iPhone location services, Photos database, Messages database, Apple ID/iCloud records, and carrier/device-location records.\n")
    (OUT / "Location_Audit_Report.md").write_text("".join(lines), encoding="utf-8")

    print(f"Google Photos April rows: {len(photo_rows)}")
    print(f"GPS rows: {len(geo_rows)}")
    print(f"IOS_PHONE rows: {len(ios_rows)}")
    print(f"Address/name hits: {len(address_rows)}")
    print(f"Report: {OUT / 'Location_Audit_Report.md'}")


if __name__ == "__main__":
    main()
