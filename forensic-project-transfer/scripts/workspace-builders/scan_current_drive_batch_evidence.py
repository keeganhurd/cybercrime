import csv
import html
import json
import re
import zipfile
from pathlib import Path


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
SOURCE_MAP = OUT / "current_takeout_zips_source_map.csv"
REPORT_CSV = OUT / "current_drive_batch_keyword_hits.csv"
REPORT_MD = OUT / "current_drive_batch_keyword_hits.md"
REPORT_HTML = OUT / "current_drive_batch_keyword_hits.html"

TERMS = [
    "HELO", "Helo Payment Services", "EIN", "IRS", "CP 575", "147C",
    "Navy Federal", "bank", "statement", "financial statement", "merchant",
    "Stripe", "Authorize.net", "Authorize", "Payanywhere", "DocuSign",
    "DoorDash", "Google Business", "Google My Business", "Business Profile",
    "Florida Crystal", "Kula Yoga", "Gmail", "Drive", "keeganhurd@gmail.com",
    "Jonathan", "Braese", "Ariana", "Robin", "Elijah", "Mom",
]

TEXT_EXTS = {".txt", ".csv", ".json", ".xml", ".html", ".htm", ".log", ".md"}
DOC_EXTS = {".docx", ".xlsx", ".pptx"}
PDF_EXTS = {".pdf"}


def clean_text(text):
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text).replace("\u202f", " ").replace("\xa0", " ")
    return re.sub(r"\s+", " ", text).strip()


def clip(text, limit=420):
    text = clean_text(text)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def read_text_file(path):
    raw = Path(path).read_bytes()
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(enc, errors="replace")
        except Exception:
            pass
    return ""


def extract_docx(path):
    texts = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.startswith("word/") and name.endswith(".xml"):
                    try:
                        texts.append(clean_text(zf.read(name).decode("utf-8", errors="replace")))
                    except Exception:
                        pass
    except Exception:
        return ""
    return " ".join(texts)


def extract_xlsx(path):
    texts = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name in ("xl/sharedStrings.xml",) or (name.startswith("xl/worksheets/") and name.endswith(".xml")):
                    try:
                        texts.append(clean_text(zf.read(name).decode("utf-8", errors="replace")))
                    except Exception:
                        pass
    except Exception:
        return ""
    return " ".join(texts)


def extract_pptx(path):
    texts = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.startswith("ppt/slides/") and name.endswith(".xml"):
                    try:
                        texts.append(clean_text(zf.read(name).decode("utf-8", errors="replace")))
                    except Exception:
                        pass
    except Exception:
        return ""
    return " ".join(texts)


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
        parts = []
        for page in reader.pages[:20]:
            try:
                parts.append(page.extract_text() or "")
            except Exception:
                pass
        return " ".join(parts)
    except Exception:
        return ""


def extract_content(path):
    p = Path(path)
    ext = p.suffix.lower()
    if ext in TEXT_EXTS:
        return read_text_file(p)
    if ext == ".docx":
        return extract_docx(p)
    if ext == ".xlsx":
        return extract_xlsx(p)
    if ext == ".pptx":
        return extract_pptx(p)
    if ext == ".pdf":
        return extract_pdf(p)
    return ""


def find_terms(text):
    low = text.lower()
    return [term for term in TERMS if term.lower() in low]


def main():
    rows = []
    with SOURCE_MAP.open("r", encoding="utf-8-sig", newline="") as f:
        source_rows = list(csv.DictReader(f))

    for src in source_rows:
        extracted = Path(src.get("ExtractedPath", ""))
        entry = src.get("EntryPath", "")
        if not entry.replace("\\", "/").startswith("Takeout/Drive/"):
            continue
        name_text = f"{extracted.name} {entry}"
        name_terms = find_terms(name_text)
        content = ""
        content_terms = []
        snippet = ""
        kind = "Filename/path only"
        if extracted.exists() and extracted.is_file():
            content = extract_content(extracted)
            content_terms = find_terms(content)
            if content_terms:
                kind = "Content text"
                first_term = content_terms[0]
                m = re.search(re.escape(first_term), content, re.I)
                if m:
                    start = max(0, m.start() - 160)
                    end = min(len(content), m.end() + 260)
                    snippet = clip(content[start:end])
        terms = sorted(set(name_terms + content_terms), key=lambda x: x.lower())
        if not terms:
            continue
        rows.append({
            "HitType": kind,
            "MatchedTerms": "; ".join(terms),
            "SourceZipFilename": src.get("SourceZipFilename", ""),
            "SourceZip": src.get("SourceZip", ""),
            "EntryPath": entry,
            "ExtractedPath": str(extracted),
            "Filename": extracted.name,
            "Extension": extracted.suffix.lower(),
            "EntrySize": src.get("EntrySize", ""),
            "EntryModified": src.get("EntryModified", ""),
            "Snippet": snippet,
            "ForensicNote": "Drive export file/content hit; this proves file presence in exported Drive content, not a view/open/download event.",
        })

    headers = [
        "HitType", "MatchedTerms", "SourceZipFilename", "SourceZip", "EntryPath",
        "ExtractedPath", "Filename", "Extension", "EntrySize", "EntryModified",
        "Snippet", "ForensicNote",
    ]
    with REPORT_CSV.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    important = [
        r for r in rows
        if re.search(r"helo|ein|irs|navy|bank|statement|merchant|stripe|authorize|payanywhere|docusign|business profile|google business|kula|florida crystal", r["MatchedTerms"], re.I)
    ]
    with REPORT_MD.open("w", encoding="utf-8") as f:
        f.write("# Current Drive Batch Keyword Hits\n\n")
        f.write(f"- Drive files scanned from current batch source map: {sum(1 for r in source_rows if r.get('EntryPath','').replace('\\\\','/').startswith('Takeout/Drive/'))}\n")
        f.write(f"- Keyword-hit files: {len(rows)}\n")
        f.write(f"- Potentially important files: {len(important)}\n\n")
        f.write("These are Drive export file/content hits. They show exported Drive content or filenames, not user access/open/download events.\n\n")
        f.write("## Potentially Important Hits\n\n")
        for r in important[:80]:
            f.write(f"- `{r['Filename']}` | terms: {r['MatchedTerms']} | source ZIP: `{r['SourceZipFilename']}` | entry: `{r['EntryPath']}`\n")
            if r["Snippet"]:
                f.write(f"  - snippet: {r['Snippet']}\n")

    cards = []
    for r in important[:120]:
        cards.append(f"""
        <article class="card">
          <h3>{html.escape(r['Filename'])}</h3>
          <div class="grid">
            <b>Hit type</b><span>{html.escape(r['HitType'])}</span>
            <b>Terms</b><span>{html.escape(r['MatchedTerms'])}</span>
            <b>Source ZIP</b><span>{html.escape(r['SourceZipFilename'])}</span>
            <b>Entry path</b><span>{html.escape(r['EntryPath'])}</span>
            <b>Modified in ZIP</b><span>{html.escape(r['EntryModified'])}</span>
          </div>
          <p>{html.escape(r['Snippet'])}</p>
          <p class="note">{html.escape(r['ForensicNote'])}</p>
        </article>
        """)

    REPORT_HTML.write_text(f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Current Drive Batch Keyword Hits</title>
<style>
body{{margin:0;background:#0e1116;color:#edf2f7;font:16px/1.5 Segoe UI,system-ui,sans-serif}}
header{{background:#0a0d12;border-bottom:4px solid #6aa6ff;padding:18px 24px;position:sticky;top:0}}
main{{max-width:1200px;margin:auto;padding:18px}}
.summary,.card{{background:#151b23;border:1px solid #303946;border-radius:8px;padding:14px;margin:14px 0}}
.summary{{border-left:8px solid #78e5aa}}
h1{{margin:0 0 4px}} h3{{color:#b9dcff;margin-top:0}}
.grid{{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 12px}}
b{{color:#ffe2a3}} span{{overflow-wrap:anywhere}} .note{{color:#aab4c3}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr}}header{{position:static}}}}
</style></head><body>
<header><h1>Current Drive Batch Keyword Hits</h1><p>Source-ZIP-traceable keyword scan of newly extracted Drive export files.</p></header>
<main>
<section class="summary">
<p><strong>{len(rows)}</strong> keyword-hit Drive files. <strong>{len(important)}</strong> potentially important hits.</p>
<p>These records show file/content presence in exported Drive content. They do not prove file open/view/download activity.</p>
</section>
{''.join(cards)}
</main></body></html>
""", encoding="utf-8")

    print(f"Keyword-hit files: {len(rows)}")
    print(f"Potentially important hits: {len(important)}")
    print(f"CSV: {REPORT_CSV}")
    print(f"MD: {REPORT_MD}")
    print(f"HTML: {REPORT_HTML}")


if __name__ == "__main__":
    main()
