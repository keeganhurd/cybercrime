import csv
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
APRIL_CSV = OUT / "parts_026_048_april_2024_hits.csv"
SHEET = OUT / "parts_026_048_april_2024_contact_sheet.jpg"
INDEX = OUT / "parts_026_048_april_2024_media_index.csv"


METADATA_SUFFIXES = [
    ".supplemental-metadata.json",
    ".supplemental-meta.json",
    ".supplemental-metad.json",
    ".supplemental-metada.json",
    ".supplemental-me.json",
    ".supplemental-.json",
    ".supplemental.json",
    ".suppl.json",
    ".json",
]


def media_for_metadata(path: Path) -> Path | None:
    name = path.name
    for suffix in METADATA_SUFFIXES:
        if name.endswith(suffix):
            candidate = path.with_name(name[: -len(suffix)])
            if candidate.exists():
                return candidate
    return None


def main():
    rows = []
    with APRIL_CSV.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            meta = Path(row["ExtractedPath"])
            media = media_for_metadata(meta)
            item = dict(row)
            item["MediaPath"] = str(media) if media else ""
            item["MediaExists"] = "Yes" if media and media.exists() else "No"
            rows.append(item)

    with INDEX.open("w", encoding="utf-8-sig", newline="") as f:
        headers = list(rows[0].keys()) if rows else ["MediaPath", "MediaExists"]
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    thumbs = []
    for idx, row in enumerate(rows, 1):
        media = Path(row.get("MediaPath") or "")
        label = f"{idx}. {media.name or Path(row['ExtractedPath']).name}\n{row.get('MatchedText','')}\n{row.get('SourceZipFilename','')}"
        if not media.exists() or media.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp", ".gif"}:
            thumbs.append((None, label + "\n[no still preview]"))
            continue
        try:
            img = Image.open(media)
            img.thumbnail((240, 180))
            tile = Image.new("RGB", (260, 250), "#111827")
            x = (260 - img.width) // 2
            tile.paste(img.convert("RGB"), (x, 10))
            thumbs.append((tile, label))
        except Exception as exc:
            thumbs.append((None, label + f"\n[preview error: {exc}]"))

    cols = 4
    tile_w, tile_h = 300, 310
    rows_count = max(1, (len(thumbs) + cols - 1) // cols)
    sheet = Image.new("RGB", (cols * tile_w, rows_count * tile_h), "#0b0f14")
    draw = ImageDraw.Draw(sheet)
    try:
        font = ImageFont.truetype("arial.ttf", 14)
    except Exception:
        font = ImageFont.load_default()

    for i, (tile, label) in enumerate(thumbs):
        col = i % cols
        row = i // cols
        x = col * tile_w
        y = row * tile_h
        draw.rectangle([x + 4, y + 4, x + tile_w - 6, y + tile_h - 6], outline="#334155", fill="#111827")
        if tile:
            sheet.paste(tile, (x + 20, y + 10))
        else:
            draw.rectangle([x + 20, y + 10, x + 280, y + 260], outline="#475569", fill="#1f2937")
        draw.multiline_text((x + 12, y + 230), label[:220], fill="#e5e7eb", font=font, spacing=3)

    sheet.save(SHEET, quality=88)
    print(f"April media rows: {len(rows)}")
    print(f"Contact sheet: {SHEET}")
    print(f"Index: {INDEX}")


if __name__ == "__main__":
    main()
