import csv
import datetime as dt
import hashlib
import html
import json
import math
import re
from pathlib import Path

from PIL import Image, ImageOps


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
TAKEOUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted")
PHONE_EVENTS = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA\Unique_Capture_Send_Events.csv")
LOCATION_CSV = OUT / "Location_Audit_Google_Photos_April19_26.csv"

REPORT_CSV = OUT / "Google_Photos_Phone_Artifact_Corroboration.csv"
REPORT_MD = OUT / "Google_Photos_Phone_Artifact_Corroboration.md"
REPORT_HTML = OUT / "Google_Photos_Phone_Artifact_Corroboration.html"

UTC = dt.timezone.utc
EASTERN = dt.timezone(dt.timedelta(hours=-4), "EDT")


def parse_dt(value):
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def to_eastern_from_utc(value):
    naive = parse_dt(value)
    if not naive:
        return None
    return naive.replace(tzinfo=UTC).astimezone(EASTERN).replace(tzinfo=None)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def image_meta(path):
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"exists": False}
    try:
        with Image.open(p) as im:
            dpi = im.info.get("dpi", ("", ""))
            return {
                "exists": True,
                "width": im.width,
                "height": im.height,
                "format": im.format,
                "mode": im.mode,
                "dpi_x": round(float(dpi[0]), 3) if dpi and dpi[0] else "",
                "dpi_y": round(float(dpi[1]), 3) if dpi and len(dpi) > 1 and dpi[1] else "",
                "sha256": sha256(p),
            }
    except Exception as exc:
        return {"exists": True, "error": str(exc)}


def ahash(path, size=16):
    try:
        with Image.open(path) as im:
            im = ImageOps.grayscale(im)
            im.thumbnail((420, 900))
            im = im.resize((size, size))
            pixels = list(im.getdata())
            avg = sum(pixels) / len(pixels)
            bits = 0
            for pix in pixels:
                bits = (bits << 1) | (1 if pix >= avg else 0)
            return bits
    except Exception:
        return None


def hamming(a, b):
    if a is None or b is None:
        return None
    return (a ^ b).bit_count()


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(TAKEOUT.resolve()))
    except Exception:
        return str(path or "")


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def clean_text(value, limit=260):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[: limit - 1] + "…" if len(text) > limit else text


def load_phone_events():
    rows = []
    with PHONE_EVENTS.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            cap = parse_dt(row.get("ScreenshotFilenameTimestamp"))
            sent = parse_dt(row.get("MessagesHtmlTextedToMomTimestamp"))
            if row.get("EventType") != "Screenshot transmission":
                continue
            meta_path = row.get("HtmlMediaFilePath") or row.get("TimestampedScreenshotFilePath")
            meta = image_meta(meta_path)
            rows.append({
                "CanonicalEventId": row.get("CanonicalEventId"),
                "Exhibit": row.get("PrimaryExhibitNumber"),
                "CaptureTime": cap,
                "SentTime": sent,
                "ElapsedSeconds": row.get("ElapsedSeconds"),
                "HtmlMediaFilePath": meta_path,
                "HtmlMediaFileName": row.get("HtmlMediaFileName"),
                "PrimarySHA256": row.get("PrimarySHA256"),
                "Category": row.get("OCRSensitiveCategory"),
                "KeyTerms": row.get("OCRKeyTerms"),
                "VisualDescription": row.get("VisualDescription"),
                "Width": meta.get("width", ""),
                "Height": meta.get("height", ""),
                "DpiX": meta.get("dpi_x", ""),
                "DpiY": meta.get("dpi_y", ""),
                "Hash": ahash(meta_path) if meta.get("exists") else None,
            })
    return rows


def load_google_photos_rows():
    rows = []
    if not LOCATION_CSV.exists():
        return rows
    with LOCATION_CSV.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            title = row.get("Title") or ""
            media_path = row.get("MediaPath") or ""
            eastern = to_eastern_from_utc(row.get("TimestampUTC"))
            if not eastern:
                continue
            if not (dt.datetime(2024, 4, 19) <= eastern <= dt.datetime(2024, 4, 26, 23, 59, 59)):
                continue
            meta = image_meta(media_path)
            rows.append({
                "GooglePhotosTimeEastern": eastern,
                "GooglePhotosTimeUTC": row.get("TimestampUTC"),
                "Title": title,
                "MediaPath": media_path,
                "MetadataPath": row.get("ExtractedPath") or "",
                "Latitude": row.get("Latitude") or "",
                "Longitude": row.get("Longitude") or "",
                "GooglePhotosOrigin": row.get("GooglePhotosOrigin") or "",
                "SourceZipFilename": row.get("SourceZipFilename") or "",
                "EntryPath": row.get("EntryPath") or "",
                "Width": meta.get("width", ""),
                "Height": meta.get("height", ""),
                "DpiX": meta.get("dpi_x", ""),
                "DpiY": meta.get("dpi_y", ""),
                "Format": meta.get("format", ""),
                "SHA256": meta.get("sha256", ""),
                "Hash": ahash(media_path) if meta.get("exists") else None,
            })
    return rows


def classify(delta_seconds, ham):
    abs_delta = abs(delta_seconds) if delta_seconds is not None else math.inf
    if ham is not None and ham <= 6 and abs_delta <= 120:
        return "Strong visual/timing match"
    if abs_delta <= 30:
        return "Strong timing match"
    if abs_delta <= 120:
        return "Close timing match"
    if abs_delta <= 300:
        return "Same short sequence"
    return "No close match"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    phone = load_phone_events()
    photos = load_google_photos_rows()

    matches = []
    for ce in phone:
        cap = ce["CaptureTime"]
        if not cap:
            continue
        best = None
        for gp in photos:
            if not gp["GooglePhotosTimeEastern"]:
                continue
            delta = int((gp["GooglePhotosTimeEastern"] - cap).total_seconds())
            if abs(delta) > 600:
                continue
            ham = hamming(ce["Hash"], gp["Hash"])
            same_dim = str(ce["Width"]) == str(gp["Width"]) and str(ce["Height"]) == str(gp["Height"])
            score = (abs(delta), 999 if ham is None else ham, 0 if same_dim else 1)
            if best is None or score < best["Score"]:
                best = {"Google": gp, "Delta": delta, "Hamming": ham, "SameDimensions": same_dim, "Score": score}
        if best:
            gp = best["Google"]
            matches.append({
                "CanonicalEventId": ce["CanonicalEventId"],
                "Exhibit": ce["Exhibit"],
                "CaptureTimeEastern": ce["CaptureTime"].isoformat(sep=" ") if ce["CaptureTime"] else "",
                "TextedTimeEastern": ce["SentTime"].isoformat(sep=" ") if ce["SentTime"] else "",
                "CaptureToTextSeconds": ce["ElapsedSeconds"],
                "GooglePhotosTitle": gp["Title"],
                "GooglePhotosTimeEastern": gp["GooglePhotosTimeEastern"].isoformat(sep=" "),
                "GooglePhotosTimeUTC": gp["GooglePhotosTimeUTC"],
                "GooglePhotosMinusCaptureSeconds": best["Delta"],
                "MatchClassification": classify(best["Delta"], best["Hamming"]),
                "VisualHashHammingDistance": "" if best["Hamming"] is None else best["Hamming"],
                "SameDimensions": "Yes" if best["SameDimensions"] else "No",
                "PhoneImageDimensions": f"{ce['Width']}x{ce['Height']}",
                "GooglePhotosDimensions": f"{gp['Width']}x{gp['Height']}",
                "PhoneImageDPI": f"{ce['DpiX']}x{ce['DpiY']}",
                "GooglePhotosImageDPI": f"{gp['DpiX']}x{gp['DpiY']}",
                "GooglePhotosOrigin": gp["GooglePhotosOrigin"],
                "Latitude": gp["Latitude"],
                "Longitude": gp["Longitude"],
                "SourceZipFilename": gp["SourceZipFilename"],
                "GooglePhotosMediaPath": gp["MediaPath"],
                "GooglePhotosMetadataPath": gp["MetadataPath"],
                "PhoneHtmlMediaPath": ce["HtmlMediaFilePath"],
                "PhoneHtmlMediaName": ce["HtmlMediaFileName"],
                "OCRSensitiveCategory": ce["Category"],
                "OCRKeyTerms": ce["KeyTerms"],
                "VisualDescription": ce["VisualDescription"],
            })

    headers = [
        "CanonicalEventId", "Exhibit", "CaptureTimeEastern", "TextedTimeEastern", "CaptureToTextSeconds",
        "GooglePhotosTitle", "GooglePhotosTimeEastern", "GooglePhotosTimeUTC", "GooglePhotosMinusCaptureSeconds",
        "MatchClassification", "VisualHashHammingDistance", "SameDimensions", "PhoneImageDimensions",
        "GooglePhotosDimensions", "PhoneImageDPI", "GooglePhotosImageDPI", "GooglePhotosOrigin",
        "Latitude", "Longitude", "SourceZipFilename", "GooglePhotosMediaPath", "GooglePhotosMetadataPath",
        "PhoneHtmlMediaPath", "PhoneHtmlMediaName", "OCRSensitiveCategory", "OCRKeyTerms", "VisualDescription",
    ]
    with REPORT_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(matches)

    strong = [m for m in matches if "Strong" in m["MatchClassification"] or m["MatchClassification"] == "Close timing match"]
    ios = [r for r in photos if "IOS_PHONE" in r["GooglePhotosOrigin"]]
    apr25_seq = [
        r for r in photos
        if dt.datetime(2024, 4, 25, 12, 0, 0) <= r["GooglePhotosTimeEastern"] <= dt.datetime(2024, 4, 25, 14, 30, 0)
    ]
    direct_drive_like = [
        m for m in matches
        if re.search(r"drive|gmail|ein|helo|navy|bank|statement|merchant|business|google", f"{m['OCRSensitiveCategory']} {m['OCRKeyTerms']} {m['VisualDescription']}", re.I)
    ]

    with REPORT_MD.open("w", encoding="utf-8") as f:
        f.write("# Google Photos / Phone Artifact Corroboration\n\n")
        f.write("## Plain-English Summary\n\n")
        f.write(f"- Google Photos April 19-26 rows reviewed: {len(photos)}\n")
        f.write(f"- Google Photos rows showing IOS_PHONE origin: {len(ios)}\n")
        f.write(f"- Google Photos rows in the April 25 noon-to-2:30 PM Eastern sequence: {len(apr25_seq)}\n")
        f.write(f"- Phone screenshot events with a Google Photos row within 10 minutes: {len(matches)}\n")
        f.write(f"- Close/strong timing or visual matches: {len(strong)}\n")
        f.write(f"- Close matched rows involving Drive/Gmail/business/financial terms: {len(direct_drive_like)}\n\n")
        f.write("This corroborates timing and iOS-device origin. It does not identify who physically held the phone.\n\n")
        f.write("## Strongest Corroboration Rows\n\n")
        for m in strong[:40]:
            f.write(
                f"- {m['CanonicalEventId']} / {m['Exhibit']}: capture {m['CaptureTimeEastern']}, "
                f"texted {m['TextedTimeEastern']} ({m['CaptureToTextSeconds']} sec), "
                f"Google Photos `{m['GooglePhotosTitle']}` at {m['GooglePhotosTimeEastern']} "
                f"({m['GooglePhotosMinusCaptureSeconds']} sec from capture), "
                f"origin {m['GooglePhotosOrigin']}, source ZIP `{m['SourceZipFilename']}`. "
                f"Terms: {clean_text(m['OCRKeyTerms'], 140)}\n"
            )

    rows_html = []
    for m in matches[:140]:
        important = "important" if re.search(r"ein|helo|navy|bank|statement|merchant|business|drive|gmail", f"{m['OCRKeyTerms']} {m['VisualDescription']}", re.I) else ""
        media_uri = Path(m["GooglePhotosMediaPath"]).as_uri() if m["GooglePhotosMediaPath"] and Path(m["GooglePhotosMediaPath"]).exists() else ""
        rows_html.append(f"""
        <article class="card {important}">
          <div class="text">
            <div class="id">{esc(m['CanonicalEventId'])} / {esc(m['Exhibit'])} / {esc(m['MatchClassification'])}</div>
            <div class="grid">
              <b>Capture</b><span>{esc(m['CaptureTimeEastern'])}</span>
              <b>Texted</b><span>{esc(m['TextedTimeEastern'])} ({esc(m['CaptureToTextSeconds'])} sec)</span>
              <b>Google Photos</b><span>{esc(m['GooglePhotosTitle'])} at {esc(m['GooglePhotosTimeEastern'])}</span>
              <b>Photos delta</b><span>{esc(m['GooglePhotosMinusCaptureSeconds'])} seconds from capture</span>
              <b>Origin</b><span>{esc(m['GooglePhotosOrigin'])}</span>
              <b>Image size</b><span>Phone {esc(m['PhoneImageDimensions'])} @ {esc(m['PhoneImageDPI'])}; Photos {esc(m['GooglePhotosDimensions'])} @ {esc(m['GooglePhotosImageDPI'])}</span>
              <b>Source ZIP</b><span>{esc(m['SourceZipFilename'])}</span>
            </div>
            <p><strong>Simple Explanation:</strong> The recovered message artifact has a screenshot capture time and texted-to-Mom time. Google Photos has a separate metadata row for a nearby iOS-origin image. This supports timing/device-origin corroboration, but does not identify the physical user.</p>
            <p class="desc">{esc(clean_text(m['VisualDescription'], 420))}</p>
          </div>
          {f'<img src="{esc(media_uri)}" alt="{esc(m["GooglePhotosTitle"])}">' if media_uri else ''}
        </article>
        """)

    REPORT_HTML.write_text(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Google Photos / Phone Artifact Corroboration</title>
<style>
:root {{ color-scheme: dark; --bg:#111318; --panel:#1b1f29; --line:#344052; --text:#e7ebf3; --muted:#aeb7c8; --blue:#7bb7ff; --green:#8bd88b; --orange:#ffbc6b; --red:#ff7f87; --purple:#c9a3ff; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:16px/1.5 "Segoe UI", system-ui, sans-serif; }}
header {{ position:sticky; top:0; z-index:2; background:#0d1016f2; border-bottom:1px solid var(--line); padding:18px 24px; }}
h1 {{ margin:0 0 6px; font-size:24px; }}
.summary {{ display:flex; flex-wrap:wrap; gap:10px; color:var(--muted); }}
.pill {{ border:1px solid var(--line); border-radius:6px; padding:6px 9px; background:#161b24; }}
main {{ padding:18px; max-width:1500px; margin:auto; }}
.card {{ display:grid; grid-template-columns:minmax(0, 2fr) minmax(260px, 1fr); gap:18px; border:1px solid var(--line); background:var(--panel); border-radius:8px; padding:16px; margin:14px 0; }}
.card.important {{ border-color:#85621f; box-shadow:0 0 0 1px #85621f inset; }}
.id {{ color:var(--blue); font-weight:800; margin-bottom:12px; }}
.grid {{ display:grid; grid-template-columns:150px minmax(0, 1fr); gap:5px 12px; }}
b {{ color:var(--orange); }}
.grid span {{ color:#dce5f8; overflow-wrap:anywhere; }}
p {{ margin:12px 0 0; }}
.desc {{ color:var(--muted); }}
img {{ width:100%; max-height:620px; object-fit:contain; background:#0a0c10; border:1px solid #2c3544; border-radius:6px; }}
@media (max-width: 860px) {{ .card {{ grid-template-columns:1fr; }} .grid {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<header>
  <h1>Google Photos / Phone Artifact Corroboration</h1>
  <div class="summary">
    <span class="pill">{len(photos)} Google Photos April rows</span>
    <span class="pill">{len(ios)} IOS_PHONE origin rows</span>
    <span class="pill">{len(apr25_seq)} April 25 noon-session Photos rows</span>
    <span class="pill">{len(matches)} phone events with nearby Photos rows</span>
    <span class="pill">{len(strong)} close/strong matches</span>
  </div>
</header>
<main>
  <p><strong>Bottom line:</strong> This page compares recovered message-thread screenshot events against Google Photos metadata. A match supports timing and iOS-device-origin corroboration. It does not prove who physically used the phone.</p>
  {''.join(rows_html)}
</main>
</body>
</html>
""", encoding="utf-8")

    print(f"Google Photos rows: {len(photos)}")
    print(f"IOS_PHONE rows: {len(ios)}")
    print(f"April 25 noon sequence rows: {len(apr25_seq)}")
    print(f"Phone events with nearby Google Photos rows: {len(matches)}")
    print(f"Close/strong matches: {len(strong)}")
    print(f"CSV: {REPORT_CSV}")
    print(f"MD: {REPORT_MD}")
    print(f"HTML: {REPORT_HTML}")


if __name__ == "__main__":
    main()
