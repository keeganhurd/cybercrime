import csv
import html
import re
from pathlib import Path


OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
BASE = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images" / "index_dark_with_device_metadata.html"
DEST = OUT / "Case_Presentation_Dark" / "Integrated_Takeout_With_Images" / "index_dark_with_device_and_photos_corroboration.html"
CORR = OUT / "Google_Photos_Phone_Artifact_Corroboration.csv"
CORR_HTML = OUT / "Google_Photos_Phone_Artifact_Corroboration.html"


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def short(value, n=180):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[: n - 1] + "…" if len(text) > n else text


def main():
    rows = []
    with CORR.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)

    strong = [r for r in rows if "Strong" in r.get("MatchClassification", "")]
    close = [r for r in rows if r.get("MatchClassification") == "Close timing match"]
    important = [
        r for r in rows
        if ("Strong" in r.get("MatchClassification", "") or r.get("MatchClassification") == "Close timing match")
        and re.search(r"helo|ein|navy|bank|statement|merchant|business|drive|gmail|google account", f"{r.get('OCRKeyTerms','')} {r.get('VisualDescription','')}", re.I)
    ]

    top = important[:14]
    cards = []
    for r in top:
        cards.append(f"""
        <div class="photo-corroboration-card">
          <div class="pc-id">{esc(r['CanonicalEventId'])} / {esc(r['Exhibit'])} / {esc(r['MatchClassification'])}</div>
          <div class="pc-grid">
            <b>Screenshot capture</b><span>{esc(r['CaptureTimeEastern'])}</span>
            <b>Texted to Mom</b><span>{esc(r['TextedTimeEastern'])} ({esc(r['CaptureToTextSeconds'])} sec)</span>
            <b>Google Photos row</b><span>{esc(r['GooglePhotosTitle'])} at {esc(r['GooglePhotosTimeEastern'])}</span>
            <b>Photos vs capture</b><span>{esc(r['GooglePhotosMinusCaptureSeconds'])} seconds</span>
            <b>Device origin</b><span>{esc(r['GooglePhotosOrigin'])}</span>
            <b>Dimensions</b><span>Message image {esc(r['PhoneImageDimensions'])}; Photos image {esc(r['GooglePhotosDimensions'])}</span>
            <b>Source ZIP</b><span>{esc(r['SourceZipFilename']) or 'source ZIP not mapped in current source map'}</span>
            <b>Terms</b><span>{esc(r['OCRKeyTerms'])}</span>
          </div>
          <p><strong>Simple Explanation:</strong> Google Photos has an independent iOS-origin image row at essentially the same time as the recovered screenshot capture, and the message export shows that screenshot texted shortly afterward. This supports timing/device-origin corroboration, but does not identify the physical user.</p>
          <p class="pc-desc">{esc(short(r['VisualDescription'], 360))}</p>
        </div>
        """)

    standalone = CORR_HTML.as_uri()
    section = f"""
  <section class="photo-corroboration">
    <h2>Google Photos iOS-Origin Corroboration</h2>
    <div class="note protect">
      <strong>New finding from the newly extracted Takeout ZIPs:</strong>
      Google Photos metadata now corroborates a large part of the April 25 screenshot sequence. The records show
      <span class="pill google">127</span> April 19-26 Google Photos rows with <span class="pill google">IOS_PHONE</span> origin,
      <span class="pill capture">74</span> April 25 noon-session rows, and
      <span class="pill sent">{len(strong) + len(close)}</span> close/strong matches to recovered phone screenshot events.
      This supports timing and iOS-device-origin corroboration. It still does not identify who physically held the phone.
      <br><br>
      Open the standalone evidence page here:
      <a class="open-media" href="{esc(standalone)}">Google Photos / Phone Artifact Corroboration</a>
    </div>
    <div class="pc-summary">
      <div><strong>{len(rows)}</strong><span>phone events with nearby Google Photos rows</span></div>
      <div><strong>{len(strong)}</strong><span>strong visual/timing or timing matches</span></div>
      <div><strong>{len(close)}</strong><span>additional close timing matches</span></div>
      <div><strong>{len(important)}</strong><span>close/strong matches involving Gmail, Drive, EIN, HELO, bank, or business terms</span></div>
    </div>
    {''.join(cards)}
  </section>
"""

    css = """
.photo-corroboration{margin:18px 0 24px}
.pc-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:12px 0}
.pc-summary div{background:#101923;border:1px solid var(--line);border-left:7px solid #38bdf8;border-radius:8px;padding:10px}
.pc-summary strong{display:block;font-size:24px;color:#bae6fd}
.pc-summary span{color:var(--muted)}
.photo-corroboration-card{background:#101923;border:1px solid #334155;border-left:7px solid #22c55e;border-radius:8px;padding:12px;margin:12px 0}
.pc-id{font-weight:900;color:#b9dcff;margin-bottom:8px}
.pc-grid{display:grid;grid-template-columns:170px minmax(0,1fr);gap:5px 12px}
.pc-grid b{color:#ffe2a3}
.pc-grid span{overflow-wrap:anywhere}
.pc-desc{color:#aab4c3}
@media (max-width:760px){.pc-grid{grid-template-columns:1fr}.photo-corroboration-card{padding:10px}}
"""

    text = BASE.read_text(encoding="utf-8", errors="replace")
    text = text.replace("</style>", css + "\n</style>", 1)
    text = text.replace("<main>", "<main>\n" + section, 1)
    DEST.write_text(text, encoding="utf-8")
    print(f"Wrote: {DEST}")
    print(f"Standalone: {CORR_HTML}")
    print(f"Strong: {len(strong)}")
    print(f"Close: {len(close)}")
    print(f"Important: {len(important)}")


if __name__ == "__main__":
    main()
