import csv
import html
import re
from pathlib import Path


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
CORR = OUT / "Google_Photos_Phone_Artifact_Corroboration.csv"
MD = OUT / "Google_Photos_Backup_Significance_Report.md"
HTML = OUT / "Google_Photos_Backup_Significance_Report.html"
INTEGRATED_SRC = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images" / "index_dark_with_device_and_photos_corroboration.html"
INTEGRATED_DEST = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images" / "index_dark_with_backup_significance.html"


CRITICAL_IDS = ["CE-017", "CE-018", "CE-020", "CE-025", "CE-030", "CE-035", "CE-047", "CE-048", "CE-055", "CE-059"]


def esc(v):
    return html.escape("" if v is None else str(v), quote=True)


def short(v, n=240):
    s = re.sub(r"\s+", " ", str(v or "")).strip()
    return s[: n - 1] + "…" if len(s) > n else s


def read_rows():
    with CORR.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def is_strong(row):
    return "Strong" in row.get("MatchClassification", "") or row.get("MatchClassification") == "Close timing match"


def is_financial(row):
    text = f"{row.get('OCRKeyTerms','')} {row.get('VisualDescription','')}"
    return re.search(r"helo|ein|irs|navy|bank|statement|merchant|business|financial|gmail|drive|google account", text, re.I)


def main():
    rows = read_rows()
    strong = [r for r in rows if is_strong(r)]
    financial = [r for r in strong if is_financial(r)]
    critical = []
    by_id = {r["CanonicalEventId"]: r for r in rows}
    for cid in CRITICAL_IDS:
        if cid in by_id:
            critical.append(by_id[cid])

    md = []
    md.append("# Google Photos Backup Significance Report\n")
    md.append("## Bottom Line\n")
    md.append(
        "The strongest new corroborating point is that many recovered screenshot events are not only present in the "
        "Messages export. They also have matching or near-matching Google Photos metadata rows in the Takeout account. "
        "For the April 25, 2024 noon sequence, Google Photos records show IOS_PHONE-origin images at the same time, "
        "often 0-1 seconds from the screenshot capture timestamp, followed by text transmission to Mom seconds later.\n"
    )
    md.append(
        "If this Takeout is from `keeganhurd@gmail.com`, then those Google Photos records are account-side Google "
        "records showing the screenshots were backed up into that Google account. That supports the inference that the "
        "iPhone used to capture the screenshots was configured/logged in to upload photos to the `keeganhurd@gmail.com` "
        "Google Photos account at that time. This still does not, by itself, identify the physical user holding the phone.\n"
    )
    md.append("## Key Counts\n")
    md.append(f"- Google Photos April 19-26 rows reviewed: 127\n")
    md.append(f"- Google Photos rows showing IOS_PHONE origin: 127\n")
    md.append(f"- April 25 noon-to-2:30 PM Eastern Google Photos rows: 74\n")
    md.append(f"- Phone screenshot events with nearby Google Photos row: 68\n")
    md.append(f"- Close/strong timing matches: {len(strong)}\n")
    md.append(f"- Close/strong matches involving Gmail, Drive, EIN, HELO, bank, business, or financial terms: {len(financial)}\n")
    md.append("## Why This Matters\n")
    md.append("- It addresses the claim that the screenshots merely existed on Elijah's phone without evidence of how they appeared there.\n")
    md.append("- The sequence shows screenshot capture time, Google Photos backup time, and text-message transmission time lining up within seconds.\n")
    md.append("- Because Google Photos metadata is in Thomas Keegan Hurd's Google Takeout, it is an independent Google-side artifact, not only an iPhone export artifact.\n")
    md.append("- The iOS-origin and 1170x2532 screenshot dimensions are consistent with Elijah's iPhone reference dimensions and inconsistent with an iPhone 8 reference device.\n")
    md.append("- The matched screenshots include Gmail, EIN/IRS, HELO Payment Services, Navy Federal, bank statement, business record, and Google Account context.\n")
    md.append("## Important Limits\n")
    md.append("- The Google Photos rows do not name the person physically holding the phone.\n")
    md.append("- The Google Photos rows do not independently prove a Drive download/open event.\n")
    md.append("- Native iPhone records are still needed to prove deletion, attachment GUIDs, local Photos creation records, sender/recipient handles, and device ownership/possession.\n")
    md.append("- Google legal-process records would be stronger for account/session/device/IP proof than Takeout alone.\n")
    md.append("## Critical Examples\n")
    for r in critical:
        md.append(
            f"- {r['CanonicalEventId']} / {r['Exhibit']}: capture {r['CaptureTimeEastern']}; "
            f"Google Photos `{r['GooglePhotosTitle']}` at {r['GooglePhotosTimeEastern']} "
            f"({r['GooglePhotosMinusCaptureSeconds']} sec from capture); texted {r['TextedTimeEastern']} "
            f"({r['CaptureToTextSeconds']} sec after capture); origin {r['GooglePhotosOrigin']}; "
            f"terms: {r['OCRKeyTerms']}.\n"
        )
    md.append("## How This Lines Up With Reported Statements\n")
    md.append(
        "The user-provided POPD supplement excerpt says Robin described a parental sweep, finding shared photos/financial "
        "documents, taking screenshots, and providing them to her attorney. The user-provided October 1, 2024 hearing "
        "excerpt says she described finding financial statements, business names, EIN numbers, bank statements, and similar material. "
        "The recovered evidence categories match those descriptions. That corroborates the type of material described, but the "
        "statements and records still need to be authenticated through POPD/Axon, court transcript/audio, and native provider records.\n"
    )
    md.append("## Best Law-Enforcement Follow-Up\n")
    md.append("- Ask Google for Google Photos backup/upload records for April 25, 2024, including device identifiers, IP/user-agent/session data, upload timestamps, and account ID.\n")
    md.append("- Ask Google for Google Account session records showing which devices were logged into `keeganhurd@gmail.com` during April 19-26, 2024.\n")
    md.append("- Ask Apple/iCloud or examine the native iPhone extraction for Photos database records, deleted asset records, screenshot creation records, Messages attachment GUIDs, and transfer metadata.\n")
    md.append("- Compare Axon-recorded Robin statement, native sms.db/Photos.sqlite, and Google Photos upload records against the CE timeline.\n")

    MD.write_text("".join(md), encoding="utf-8")

    row_cards = []
    for r in critical:
        row_cards.append(f"""
        <article class="card">
          <h3>{esc(r['CanonicalEventId'])} / {esc(r['Exhibit'])}</h3>
          <div class="grid">
            <b>Screenshot capture</b><span>{esc(r['CaptureTimeEastern'])}</span>
            <b>Google Photos backup row</b><span>{esc(r['GooglePhotosTitle'])} at {esc(r['GooglePhotosTimeEastern'])}</span>
            <b>Backup delta</b><span>{esc(r['GooglePhotosMinusCaptureSeconds'])} seconds from capture</span>
            <b>Texted to Mom</b><span>{esc(r['TextedTimeEastern'])} ({esc(r['CaptureToTextSeconds'])} sec after capture)</span>
            <b>Google origin</b><span>{esc(r['GooglePhotosOrigin'])}</span>
            <b>Dimensions</b><span>{esc(r['PhoneImageDimensions'])}</span>
            <b>Terms</b><span>{esc(r['OCRKeyTerms'])}</span>
          </div>
          <p>{esc(short(r['VisualDescription'], 420))}</p>
        </article>
        """)

    HTML.write_text(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Google Photos Backup Significance</title>
<style>
:root {{ color-scheme:dark; --bg:#0e1116; --panel:#151b23; --line:#303946; --text:#edf2f7; --muted:#aab4c3; --blue:#6aa6ff; --green:#78e5aa; --amber:#ffe2a3; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:16px/1.5 "Segoe UI", system-ui, sans-serif; }}
header {{ background:#0a0d12; border-bottom:4px solid var(--blue); padding:18px 24px; position:sticky; top:0; }}
h1 {{ margin:0 0 6px; font-size:24px; }}
header p {{ margin:0; color:#c8d7eb; }}
main {{ max-width:1180px; margin:auto; padding:18px; }}
.box,.card {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:14px; margin:14px 0; }}
.box {{ border-left:8px solid var(--green); }}
.warn {{ border-left-color:#ffbf47; }}
.counts {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:10px; }}
.counts div {{ background:#101923; border:1px solid var(--line); border-left:7px solid var(--blue); border-radius:8px; padding:10px; }}
.counts strong {{ display:block; font-size:26px; color:#b9dcff; }}
.grid {{ display:grid; grid-template-columns:190px minmax(0,1fr); gap:6px 12px; }}
b {{ color:var(--amber); }}
span {{ overflow-wrap:anywhere; }}
h2 {{ border-bottom:1px solid var(--line); padding-bottom:6px; }}
h3 {{ color:#b9dcff; margin-top:0; }}
li {{ margin:6px 0; }}
@media(max-width:760px){{.grid{{grid-template-columns:1fr}} header{{position:static}}}}
</style>
</head>
<body>
<header>
  <h1>Google Photos Backup Significance</h1>
  <p>Objective explanation of the screenshot capture → Google Photos backup → text transmission chain.</p>
</header>
<main>
  <section class="box">
    <h2>Bottom Line</h2>
    <p>The key point is no longer just that screenshots existed on Elijah's phone. The stronger point is that many screenshot events have matching Google Photos metadata rows in the Takeout account, often 0-1 seconds from the screenshot capture time, followed by text transmission to Mom seconds later.</p>
    <p>If this Takeout is from <code>keeganhurd@gmail.com</code>, then these are Google-side account records showing the screenshots backed up into that Google Photos account. That supports the inference that the iPhone was configured/logged in to upload photos to the account at the time. This does not, by itself, identify the person holding the phone.</p>
  </section>
  <section class="counts">
    <div><strong>127</strong><span>Google Photos April 19-26 rows</span></div>
    <div><strong>127</strong><span>IOS_PHONE origin rows</span></div>
    <div><strong>74</strong><span>April 25 noon-session rows</span></div>
    <div><strong>{len(strong)}</strong><span>close/strong timing matches</span></div>
    <div><strong>{len(financial)}</strong><span>matches involving financial/business/Google terms</span></div>
  </section>
  <section class="box warn">
    <h2>Limits</h2>
    <ul>
      <li>These records do not name the physical user.</li>
      <li>They do not replace native iPhone Photos/Messages records.</li>
      <li>They do not independently prove a Drive open/download event.</li>
      <li>Provider records from Google and Apple would be stronger for device, IP, session, and deletion proof.</li>
    </ul>
  </section>
  <h2>Critical Examples</h2>
  {''.join(row_cards)}
</main>
</body>
</html>
""", encoding="utf-8")

    if INTEGRATED_SRC.exists():
        section = f"""
  <section class="note protect">
    <h2>Google Photos Backup Significance</h2>
    <p><strong>Plain-language point:</strong> the screenshots were not only found in the iPhone message export. Google Photos metadata in the Takeout account shows iOS-origin image rows at the same times as many screenshot captures, often 0-1 seconds apart, followed by text-message transmission seconds later.</p>
    <p>If this Takeout is from <code>keeganhurd@gmail.com</code>, this supports the inference that the iPhone used to capture the screenshots was configured/logged in to back up photos to that Google Photos account. It does not, standing alone, identify the physical user.</p>
    <p><a class="open-media" href="{esc(HTML.as_uri())}">Open Google Photos Backup Significance Report</a></p>
  </section>
"""
        text = INTEGRATED_SRC.read_text(encoding="utf-8", errors="replace")
        text = text.replace("<main>", "<main>\n" + section, 1)
        INTEGRATED_DEST.write_text(text, encoding="utf-8")

    print(f"Wrote: {MD}")
    print(f"Wrote: {HTML}")
    if INTEGRATED_DEST.exists():
        print(f"Wrote: {INTEGRATED_DEST}")
    print(f"Strong/close matches: {len(strong)}")
    print(f"Financial/business/Google matches: {len(financial)}")


if __name__ == "__main__":
    main()
