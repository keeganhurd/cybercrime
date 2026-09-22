import csv
import html
import re
from pathlib import Path


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
STRICT = OUT / "current_drive_batch_strict_evidence_hits.csv"
HTML_OUT = OUT / "Drive_Content_Batch_11_002_006_Significance_Report.html"
MD_OUT = OUT / "Drive_Content_Batch_11_002_006_Significance_Report.md"
INTEGRATED_SRC = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images" / "index_dark_with_backup_significance.html"
INTEGRATED_DEST = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images" / "index_dark_with_backup_and_drive_content.html"

PRIORITY = [
    "HELO Payment Services", "HELO", "Navy Federal", "Bank Statement",
    "Business Checking", "Payanywhere", "Stripe", "DocuSign",
    "Google Business", "Florida Crystal", "Kula Yoga", "Gmail address",
    "Jonathan Braese", "Robin", "Elijah", "Ariana",
]


def esc(v):
    return html.escape("" if v is None else str(v), quote=True)


def score(row):
    text = row.get("MatchedTerms", "")
    score_val = 0
    for i, term in enumerate(PRIORITY):
        if term.lower() in text.lower():
            score_val += 100 - i
    if row.get("MatchLocation") == "Content":
        score_val += 20
    return score_val


def load_rows():
    with STRICT.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    rows.sort(key=score, reverse=True)
    return rows


def contains(row, *terms):
    text = row.get("MatchedTerms", "").lower() + " " + row.get("EntryPath", "").lower() + " " + row.get("Filename", "").lower()
    return any(term.lower() in text for term in terms)


def main():
    rows = load_rows()
    helo = [r for r in rows if contains(r, "helo")]
    navy = [r for r in rows if contains(r, "navy federal", "bank statement", "business checking")]
    legal = [r for r in rows if "hurd family legal" in r.get("EntryPath", "").lower()]
    kula = [r for r in rows if contains(r, "kula yoga")]

    top = []
    seen = set()
    for group in (helo, navy, legal, kula, rows):
        for r in group:
            key = r.get("EntryPath")
            if key not in seen:
                top.append(r)
                seen.add(key)
            if len(top) >= 18:
                break
        if len(top) >= 18:
            break

    md = []
    md.append("# Drive Content Batch 11-002 Through 11-006 Significance Report\n\n")
    md.append("## Bottom Line\n\n")
    md.append(
        "Takeout ZIPs `11-002` through `11-006` are Drive export content. They produced source-ZIP-traceable files "
        "containing HELO Payment Services, Navy Federal, Venmo, Stripe, Payanywhere, Hurd Family Legal, Kula Yoga, "
        "and related business/financial context. This supports that these categories of documents existed in the "
        "Drive export, and overlaps with categories visible in the recovered screenshot/text-message evidence.\n\n"
    )
    md.append(
        "Important limitation: these Drive export files show file/content presence in Google Drive. They do not, by "
        "themselves, prove who opened, viewed, downloaded, or screenshot any file on April 19-26, 2024. Access/open/download "
        "proof still requires Google Drive audit/session logs or native device records.\n\n"
    )
    md.append("## Counts\n\n")
    md.append(f"- Strict Drive evidence hits: {len(rows)}\n")
    md.append(f"- HELO-related hits: {len(helo)}\n")
    md.append(f"- Navy Federal/bank-related hits: {len(navy)}\n")
    md.append(f"- Hurd Family Legal folder hits: {len(legal)}\n")
    md.append(f"- Kula Yoga folder hits: {len(kula)}\n\n")
    md.append("## Strongest Source-ZIP-Traceable Examples\n\n")
    for r in top:
        md.append(f"- `{r['Filename']}` | source ZIP `{r['SourceZipFilename']}` | terms: {r['MatchedTerms']} | entry `{r['EntryPath']}`\n")
        if r.get("Snippet"):
            md.append(f"  - snippet: {r['Snippet']}\n")
    md.append("\n## Investigative Use\n\n")
    md.append("- Use this as Drive-content corroboration, not access-log proof.\n")
    md.append("- Compare the filenames/categories here against the screenshot sequence and Robin's described categories: financial statements, business names, EIN numbers, bank statements, and similar records.\n")
    md.append("- Ask Google for actual Drive access/open/download/preview logs for the files and account during April 19-26, 2024.\n")
    MD_OUT.write_text("".join(md), encoding="utf-8")

    cards = []
    for r in top:
        cards.append(f"""
        <article class="card">
          <h3>{esc(r['Filename'])}</h3>
          <div class="grid">
            <b>Terms</b><span>{esc(r['MatchedTerms'])}</span>
            <b>Source ZIP</b><span>{esc(r['SourceZipFilename'])}</span>
            <b>Drive entry</b><span>{esc(r['EntryPath'])}</span>
            <b>Match location</b><span>{esc(r['MatchLocation'])}</span>
          </div>
          <p>{esc(r['Snippet'])}</p>
        </article>
        """)

    HTML_OUT.write_text(f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Drive Content Batch 11-002 to 11-006 Significance</title>
<style>
body{{margin:0;background:#0e1116;color:#edf2f7;font:16px/1.5 Segoe UI,system-ui,sans-serif}}
header{{background:#0a0d12;border-bottom:4px solid #6aa6ff;padding:18px 24px;position:sticky;top:0}}
main{{max-width:1200px;margin:auto;padding:18px}}
.box,.card{{background:#151b23;border:1px solid #303946;border-radius:8px;padding:14px;margin:14px 0}}
.box{{border-left:8px solid #78e5aa}}
.warn{{border-left-color:#ffbf47}}
.counts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}}
.counts div{{background:#101923;border:1px solid #303946;border-left:7px solid #6aa6ff;border-radius:8px;padding:10px}}
.counts strong{{display:block;font-size:26px;color:#b9dcff}}
.grid{{display:grid;grid-template-columns:140px minmax(0,1fr);gap:6px 12px}}
h1{{margin:0 0 4px}} h3{{color:#b9dcff;margin-top:0}} b{{color:#ffe2a3}} span{{overflow-wrap:anywhere}}
@media(max-width:760px){{.grid{{grid-template-columns:1fr}}header{{position:static}}}}
</style></head><body>
<header><h1>Drive Content Batch 11-002 Through 11-006</h1><p>Source-ZIP-traceable Drive content findings. Not access-log proof.</p></header>
<main>
<section class="box">
<h2>Bottom Line</h2>
<p>These ZIPs contain exported Google Drive files. They show business, bank, HELO, Navy Federal, Venmo, Stripe, Payanywhere, Hurd Family Legal, and Kula Yoga content in the Drive export.</p>
<p>This corroborates that those categories of records existed in Drive and overlaps with categories visible in the recovered screenshot/text-message evidence.</p>
</section>
<section class="box warn"><strong>Limit:</strong> These files do not prove who opened, viewed, downloaded, or screenshotted them on April 19-26, 2024. For that, ask Google for Drive access/open/download/preview logs and compare native iPhone records.</section>
<section class="counts">
<div><strong>{len(rows)}</strong><span>strict evidence hits</span></div>
<div><strong>{len(helo)}</strong><span>HELO-related hits</span></div>
<div><strong>{len(navy)}</strong><span>Navy/bank hits</span></div>
<div><strong>{len(legal)}</strong><span>Hurd Family Legal hits</span></div>
<div><strong>{len(kula)}</strong><span>Kula Yoga hits</span></div>
</section>
<h2>Strongest Examples</h2>
{''.join(cards)}
</main></body></html>
""", encoding="utf-8")

    if INTEGRATED_SRC.exists():
        section = f"""
  <section class="note protect">
    <h2>Drive Content Batch 11-002 Through 11-006</h2>
    <p><strong>New Drive-content finding:</strong> the `11-002` through `11-006` Takeout ZIPs contain source-ZIP-traceable Drive files with HELO, Navy Federal, Venmo, Stripe, Payanywhere, Hurd Family Legal, Kula Yoga, and related business/financial content. This supports file/content presence in Drive and overlaps with the screenshot evidence categories.</p>
    <p><strong>Limit:</strong> this is Drive export content, not proof of April 2024 Drive open/view/download activity.</p>
    <p><a class="open-media" href="{esc(HTML_OUT.as_uri())}">Open Drive Content Batch Significance Report</a></p>
    <p><a class="open-media" href="{esc((OUT / 'current_drive_batch_strict_evidence_hits.html').as_uri())}">Open Strict Drive Evidence Hits</a></p>
  </section>
"""
        text = INTEGRATED_SRC.read_text(encoding="utf-8", errors="replace")
        text = text.replace("<main>", "<main>\n" + section, 1)
        INTEGRATED_DEST.write_text(text, encoding="utf-8")

    print(f"Wrote: {MD_OUT}")
    print(f"Wrote: {HTML_OUT}")
    if INTEGRATED_DEST.exists():
        print(f"Wrote: {INTEGRATED_DEST}")
    print(f"Strict hits: {len(rows)}")
    print(f"HELO hits: {len(helo)}")
    print(f"Navy/bank hits: {len(navy)}")


if __name__ == "__main__":
    main()
