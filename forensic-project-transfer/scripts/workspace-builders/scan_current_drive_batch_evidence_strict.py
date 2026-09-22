import csv
import html
import re
import zipfile
from pathlib import Path


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
SOURCE_MAP = OUT / "current_takeout_zips_source_map.csv"
REPORT_CSV = OUT / "current_drive_batch_strict_evidence_hits.csv"
REPORT_MD = OUT / "current_drive_batch_strict_evidence_hits.md"
REPORT_HTML = OUT / "current_drive_batch_strict_evidence_hits.html"

PATTERNS = {
    "HELO Payment Services": r"\bHELO\s+Payment\s+Services\b",
    "HELO": r"\bHELO\b",
    "EIN": r"\bEIN\b",
    "IRS": r"\bIRS\b",
    "CP 575": r"\bCP\s*575\b",
    "147C": r"\b147C\b",
    "Navy Federal": r"\bNavy\s+Federal\b",
    "Bank Statement": r"\bBank\s+Statement\b|\bStatement\s+of\s+Account\b",
    "Business Checking": r"\bBusiness\s+Checking\b",
    "Merchant": r"\bMerchant\b",
    "Stripe": r"\bStripe\b",
    "Authorize.net": r"\bAuthorize\.net\b",
    "Payanywhere": r"\bPayanywhere\b",
    "DocuSign": r"\bDocuSign\b",
    "DoorDash": r"\bDoorDash\b",
    "Google Business": r"\bGoogle\s+(?:My\s+)?Business\b|\bBusiness\s+Profile\b",
    "Florida Crystal": r"\bFlorida\s+Crystal\b",
    "Kula Yoga": r"\bKula\s+Yoga\b",
    "Gmail address": r"\bkeeganhurd@gmail\.com\b|\bthomaskhurd@gmail\.com\b",
    "Jonathan Braese": r"\bJonathan\s+Brae?s[ea]?\b|\bBraese\b|\bBreas\b",
    "Robin": r"\bRobin\b",
    "Elijah": r"\bElijah\b",
    "Ariana": r"\bAriana\b",
    "84-2520853": r"\b84-2520853\b",
    "7103475617": r"\b7103475617\b",
}

TEXT_EXTS = {".txt", ".csv", ".json", ".xml", ".html", ".htm", ".log", ".md"}


def clean_text(text):
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text).replace("\u202f", " ").replace("\xa0", " ")
    return re.sub(r"\s+", " ", text).strip()


def clip(text, term=None, limit=520):
    text = clean_text(text)
    if term:
        pat = PATTERNS.get(term)
        if pat:
            m = re.search(pat, text, re.I)
            if m:
                start = max(0, m.start() - 180)
                end = min(len(text), m.end() + 340)
                text = text[start:end]
    return text[: limit - 1] + "…" if len(text) > limit else text


def read_text_file(path):
    raw = Path(path).read_bytes()
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(enc, errors="replace")
        except Exception:
            pass
    return ""


def extract_ooxml(path, prefixes):
    parts = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if any(name.startswith(prefix) for prefix in prefixes) and name.endswith(".xml"):
                    try:
                        parts.append(clean_text(zf.read(name).decode("utf-8", errors="replace")))
                    except Exception:
                        pass
    except Exception:
        return ""
    return " ".join(parts)


def extract_pdf(path):
    try:
        from pypdf import PdfReader
    except Exception:
        try:
            from PyPDF2 import PdfReader
        except Exception:
            return ""
    try:
        reader = PdfReader(str(path))
        return " ".join((page.extract_text() or "") for page in reader.pages[:25])
    except Exception:
        return ""


def extract_content(path):
    p = Path(path)
    ext = p.suffix.lower()
    if ext in TEXT_EXTS:
        return read_text_file(p)
    if ext == ".docx":
        return extract_ooxml(p, ["word/"])
    if ext == ".xlsx":
        return extract_ooxml(p, ["xl/sharedStrings.xml", "xl/worksheets/"])
    if ext == ".pptx":
        return extract_ooxml(p, ["ppt/slides/"])
    if ext == ".pdf":
        return extract_pdf(p)
    return ""


def find_matches(text):
    found = []
    for label, pattern in PATTERNS.items():
        if re.search(pattern, text or "", re.I):
            found.append(label)
    return found


def main():
    with SOURCE_MAP.open("r", encoding="utf-8-sig", newline="") as f:
        source_rows = list(csv.DictReader(f))

    rows = []
    drive_rows = [r for r in source_rows if r.get("EntryPath", "").replace("\\", "/").startswith("Takeout/Drive/")]
    for src in drive_rows:
        path = Path(src.get("ExtractedPath", ""))
        entry = src.get("EntryPath", "")
        name_matches = find_matches(f"{path.name} {entry}")
        content = extract_content(path) if path.exists() and path.is_file() else ""
        content_matches = find_matches(content)
        matches = list(dict.fromkeys(name_matches + content_matches))
        if not matches:
            continue
        first_content = content_matches[0] if content_matches else (matches[0] if matches else None)
        rows.append({
            "MatchedTerms": "; ".join(matches),
            "MatchLocation": "Content" if content_matches else "Filename/path",
            "SourceZipFilename": src.get("SourceZipFilename", ""),
            "SourceZip": src.get("SourceZip", ""),
            "EntryPath": entry,
            "ExtractedPath": str(path),
            "Filename": path.name,
            "Extension": path.suffix.lower(),
            "EntrySize": src.get("EntrySize", ""),
            "EntryModified": src.get("EntryModified", ""),
            "Snippet": clip(content or f"{path.name} {entry}", first_content),
            "ForensicNote": "Drive export file/content hit. Shows exported Drive content or filename; does not prove April 2024 open/view/download activity.",
        })

    def score(row):
        terms = row["MatchedTerms"].lower()
        high = ["helo payment", "84-2520853", "navy federal", "bank statement", "business checking", "7103475617", "cp 575", "147c", "google business", "florida crystal", "kula yoga", "docusign", "payanywhere"]
        return sum(10 for h in high if h in terms) + len(row["MatchedTerms"].split("; "))

    rows.sort(key=score, reverse=True)

    headers = [
        "MatchedTerms", "MatchLocation", "SourceZipFilename", "SourceZip", "EntryPath",
        "ExtractedPath", "Filename", "Extension", "EntrySize", "EntryModified",
        "Snippet", "ForensicNote",
    ]
    with REPORT_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    with REPORT_MD.open("w", encoding="utf-8") as f:
        f.write("# Current Drive Batch Strict Evidence Hits\n\n")
        f.write(f"- Drive files scanned from current batch source map: {len(drive_rows)}\n")
        f.write(f"- Strict case-relevant hit files: {len(rows)}\n")
        f.write("- Note: these are Drive export file/content hits, not proof of April 2024 open/view/download activity.\n\n")
        f.write("## Top Hits\n\n")
        for r in rows[:80]:
            f.write(f"- `{r['Filename']}` | terms: {r['MatchedTerms']} | source ZIP: `{r['SourceZipFilename']}` | entry: `{r['EntryPath']}`\n")
            if r["Snippet"]:
                f.write(f"  - snippet: {r['Snippet']}\n")

    cards = []
    for r in rows[:100]:
        cards.append(f"""
        <article class="card">
          <h3>{html.escape(r['Filename'])}</h3>
          <div class="grid">
            <b>Terms</b><span>{html.escape(r['MatchedTerms'])}</span>
            <b>Match location</b><span>{html.escape(r['MatchLocation'])}</span>
            <b>Source ZIP</b><span>{html.escape(r['SourceZipFilename'])}</span>
            <b>Entry path</b><span>{html.escape(r['EntryPath'])}</span>
            <b>ZIP modified time</b><span>{html.escape(r['EntryModified'])}</span>
          </div>
          <p>{html.escape(r['Snippet'])}</p>
          <p class="note">{html.escape(r['ForensicNote'])}</p>
        </article>
        """)

    REPORT_HTML.write_text(f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Strict Drive Batch Evidence Hits</title>
<style>
body{{margin:0;background:#0e1116;color:#edf2f7;font:16px/1.5 Segoe UI,system-ui,sans-serif}}
header{{background:#0a0d12;border-bottom:4px solid #6aa6ff;padding:18px 24px;position:sticky;top:0}}
main{{max-width:1200px;margin:auto;padding:18px}}
.summary,.card{{background:#151b23;border:1px solid #303946;border-radius:8px;padding:14px;margin:14px 0}}
.summary{{border-left:8px solid #78e5aa}}
h1{{margin:0 0 4px}} h3{{color:#b9dcff;margin-top:0}}
.grid{{display:grid;grid-template-columns:160px minmax(0,1fr);gap:6px 12px}}
b{{color:#ffe2a3}} span{{overflow-wrap:anywhere}} .note{{color:#aab4c3}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr}}header{{position:static}}}}
</style></head><body>
<header><h1>Strict Drive Batch Evidence Hits</h1><p>Case-relevant exact-term scan of newly extracted Drive export files.</p></header>
<main>
<section class="summary">
<p><strong>{len(drive_rows)}</strong> Drive files scanned. <strong>{len(rows)}</strong> strict evidence hits.</p>
<p>These records show exported Drive content or filenames. They do not prove file open/view/download activity.</p>
</section>
{''.join(cards)}
</main></body></html>
""", encoding="utf-8")

    print(f"Drive files scanned: {len(drive_rows)}")
    print(f"Strict evidence hits: {len(rows)}")
    print(f"CSV: {REPORT_CSV}")
    print(f"MD: {REPORT_MD}")
    print(f"HTML: {REPORT_HTML}")


if __name__ == "__main__":
    main()
