from pathlib import Path
import re


folder = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Florida_Crystal_Well_Steve_Roberge_Evidence")
src = folder / "index_revised.html"
dst = folder / "index_revised_light.html"

html = src.read_text(encoding="utf-8")

light_css = """  <style>
    :root {
      color-scheme: light;
      --bg: #ffffff;
      --panel: #ffffff;
      --panel2: #f6f8fb;
      --ink: #121820;
      --line: #c8d1dc;
      --capture: #b64b00;
      --backup: #18713a;
      --transmit: #005f8f;
      --delta: #8a5a00;
      --account: #5b36a8;
      --entity: #8a4b00;
      --technical: #006b70;
      --muted-note: #5f6b78;
    }
    * { box-sizing: border-box; }
    html { scroll-padding-top: calc(var(--sticky-nav-height, 72px) + 20px); }
    body { margin: 0; padding-top: calc(var(--sticky-nav-height, 72px) + 14px); font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.48; }
    header { padding: 28px 24px 18px; border-bottom: 1px solid var(--line); background: #f6f8fb; }
    main { max-width: 1180px; margin: 0 auto; padding: 20px; }
    h1 { margin: 0; font-size: clamp(1.8rem, 4vw, 3rem); line-height: 1.08; color: #0d1b2a; }
    h2 { margin-top: 28px; color: #004e7c; }
    h3 { margin: 0 0 8px; color: #172033; }
    .subtitle { margin-top: 8px; color: var(--entity); font-weight: 800; font-size: 1.12rem; }
    .prepared { color: var(--muted-note); margin-top: 5px; }
    nav { position: fixed; top: 0; left: 0; right: 0; z-index: 1000; display: flex; flex-wrap: wrap; gap: 8px; margin-top: 0; padding: 10px 24px; background: rgba(255,255,255,.98); border-bottom: 1px solid var(--line); box-shadow: 0 5px 16px rgba(15, 23, 42, .16); max-height: 36vh; overflow-y: auto; }
    nav a { color: #0d1b2a; text-decoration: none; border: 1px solid #b9c5d3; background: #eef4fb; padding: 7px 9px; border-radius: 6px; font-weight: 800; }
    section, .card, .box { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; margin: 16px 0; }
    .first-page { border-left: 4px solid var(--entity); }
    .chain-focus { border: 2px solid var(--backup); background: #f7fff8; }
    .capture-value { color: var(--capture); font-weight: 950; }
    .backup-value { color: var(--backup); font-weight: 950; }
    .transmit-value { color: var(--transmit); font-weight: 950; }
    .delta-value { color: var(--delta); font-weight: 950; background: rgba(255, 209, 102, .22); border: 1px solid rgba(138, 90, 0, .35); border-radius: 5px; padding: 1px 5px; display: inline-block; }
    .account-value { color: var(--account); font-weight: 900; }
    .entity-value { color: var(--entity); font-weight: 900; }
    .technical-value { color: var(--technical); font-weight: 950; }
    .muted-note { color: var(--muted-note); }
    .flow { display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; gap: 10px; align-items: center; margin: 14px 0; }
    .flow div:not(.arrow) { background: #f4f7fb; border: 1px solid var(--line); border-radius: 8px; padding: 11px; min-height: 70px; }
    .flow b { display: block; color: var(--muted-note); font-size: .8rem; letter-spacing: .04em; }
    .arrow { color: var(--delta); font-weight: 900; font-size: 1.4rem; }
    .hero-grid, .evidence-layout { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(320px, .85fr); gap: 16px; align-items: start; }
    img.evidence-image { width: 100%; max-height: 520px; object-fit: contain; border-radius: 6px; background: #ffffff; border: 1px solid var(--line); }
    img.large { max-height: 620px; }
    figure { margin: 0; }
    figcaption { color: var(--muted-note); font-size: .86rem; margin-top: 6px; overflow-wrap: anywhere; }
    .badges { display: flex; flex-wrap: wrap; gap: 8px; }
    .badges span { background: #edf8ef; border: 1px solid #6ea678; color: var(--backup); padding: 6px 9px; border-radius: 999px; font-weight: 950; font-size: .82rem; }
    .mini-meta, .appendix-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; margin: 12px 0; }
    .mini-meta div, .appendix-meta div { background: #f7f9fc; border: 1px solid var(--line); border-radius: 7px; padding: 8px; }
    dt { color: var(--muted-note); font-size: .75rem; text-transform: uppercase; font-weight: 900; }
    dd { margin: 2px 0 0; overflow-wrap: anywhere; }
    table { width: 100%; border-collapse: collapse; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: var(--panel); }
    th, td { padding: 10px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); }
    th { background: #e9eff6; color: #111827; }
    tr:nth-child(even) td { background: #f8fafc; }
    .tier1-row td { border-top: 2px solid var(--entity); border-bottom: 2px solid var(--entity); background: #fff8ec !important; font-weight: 800; }
    .tier { color: var(--muted-note); text-transform: uppercase; letter-spacing: .04em; font-weight: 900; font-size: .78rem; }
    .condensed { display: grid; grid-template-columns: 170px 1fr; gap: 14px; }
    .thumb img { max-height: 220px; }
    details { background: #f8fafc; border: 1px solid var(--line); border-radius: 7px; padding: 10px; margin: 8px 0; }
    summary { color: var(--entity); cursor: pointer; font-weight: 900; }
    code { color: var(--technical); overflow-wrap: anywhere; word-break: break-word; }
    .request li { margin: 6px 0; }
    .draft { border: 1px solid var(--delta); background: #fff7df; color: var(--delta); display: inline-block; padding: 4px 8px; border-radius: 6px; font-weight: 900; }
    .chain-focus .flow { border: 1px solid rgba(24, 113, 58, .35); border-radius: 9px; padding: 8px; background: rgba(24, 113, 58, .04); }
    #timeline td:first-child { font-size: 1.02rem; font-weight: 950; }
    .card.full { border-color: rgba(138, 75, 0, .45); }

    @page { size: Letter; margin: 0.55in; }
    @media print {
      :root { color-scheme: light; }
      html { scroll-padding-top: 0; }
      body { padding-top: 0; background: #fff; color: #111; font-size: 10pt; line-height: 1.35; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      header { padding: 0 0 10pt; background: #fff; border-bottom: 1pt solid #999; }
      main { max-width: none; padding: 0; }
      nav { display: none; }
      h1 { font-size: 20pt; }
      h2 { font-size: 14pt; margin: 14pt 0 7pt; }
      h3 { font-size: 11.5pt; }
      section, .card, .box { break-inside: avoid; page-break-inside: avoid; border-color: #aaa; background: #fff; padding: 9pt; margin: 8pt 0; border-radius: 4pt; }
      .hero-grid, .evidence-layout { grid-template-columns: 1.05fr .95fr; gap: 10pt; }
      .flow { grid-template-columns: 1fr auto 1fr auto 1fr; gap: 5pt; margin: 7pt 0; }
      .flow div:not(.arrow) { min-height: auto; padding: 6pt; }
      img.evidence-image { max-height: 4.7in; border: 1pt solid #aaa; }
      img.large { max-height: 5.2in; }
      table { font-size: 8.6pt; }
      th, td { padding: 4.5pt; }
      details { break-inside: auto; page-break-inside: auto; }
      summary { color: #111; }
      a { color: inherit; text-decoration: none; }
    }
    @media (max-width: 850px) {
      main { padding: 12px; }
      header { padding: 22px 14px; }
      body { padding-top: calc(var(--sticky-nav-height, 84px) + 14px); }
      nav { padding: 8px 12px; gap: 6px; }
      .hero-grid, .evidence-layout, .condensed { grid-template-columns: 1fr; }
      .flow { grid-template-columns: 1fr; }
      .arrow { text-align: center; }
    }
  </style>"""

html = re.sub(r"  <style>.*?  </style>", light_css, html, count=1, flags=re.S)
html = html.replace(
    "<title>Florida Crystal Well & Sprinkler - Unauthorized Business Data Access Evidence</title>",
    "<title>Florida Crystal Well & Sprinkler - Unauthorized Business Data Access Evidence (Light Print)</title>",
)
html = html.replace(
    "<div class=\"prepared\">Prepared for Flagler County law-enforcement review</div>",
    "<div class=\"prepared\">Prepared for Flagler County law-enforcement review · Light print version</div>",
)

dst.write_text(html, encoding="utf-8")
print(f"Wrote {dst}")
