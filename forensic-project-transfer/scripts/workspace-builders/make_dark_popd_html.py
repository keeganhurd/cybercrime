from pathlib import Path


OUT_DIR = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet\POPD_All_Events_With_Images")
LIGHT = OUT_DIR / "index.html"
DARK = OUT_DIR / "index_dark.html"


text = LIGHT.read_text(encoding="utf-8")

text = text.replace(
    "<title>POPD All Events With Images</title>",
    "<title>POPD All Events With Images - Dark Mode</title>",
)
text = text.replace(
    "<h1>POPD All Events With Images</h1>",
    "<h1>POPD All Events With Images - Dark Mode</h1>",
)

old_vars = """  :root {
    --bg: #f6f7f9;
    --ink: #121417;
    --muted: #5d6673;
    --panel: #ffffff;
    --line: #d7dde5;
    --blue: #dfeeff;
    --blue-ink: #084a83;
    --green: #e3f7ea;
    --green-ink: #116235;
    --amber: #fff0c7;
    --amber-ink: #7a5200;
    --violet: #eee7ff;
    --violet-ink: #54319a;
    --gray: #edf0f4;
  }"""

new_vars = """  :root {
    --bg: #0e1116;
    --ink: #edf2f7;
    --muted: #aab4c3;
    --panel: #151b23;
    --line: #303946;
    --blue: #163a5f;
    --blue-ink: #b9dcff;
    --green: #173f2a;
    --green-ink: #bdf4cf;
    --amber: #533f13;
    --amber-ink: #ffe2a3;
    --violet: #342657;
    --violet-ink: #d7c7ff;
    --gray: #252d38;
  }"""

text = text.replace(old_vars, new_vars)

replacements = {
    "background: #17202b;": "background: #0a0d12;",
    "color: white;": "color: #f8fbff;",
    "color: #d7e5f7;": "color: #c8d7eb;",
    "background: #fff;": "background: #151b23;",
    "background: #f7fff9;": "background: #101f18;",
    "background: #f9fbff;": "background: #111923;",
    "background: #fbfcfe;": "background: #121922;",
    "background: #ffffff;": "background: #151b23;",
    "background: #fff8e5;": "background: #2b230f;",
    "background: #eef8ff;": "background: #102133;",
    "background: #f6f0ff;": "background: #1d1730;",
    "background: #f1f4f8;": "background: #0f141b;",
    "background: #dfe4eb;": "background: #0b0f14;",
    "background: #111;": "background: #050608;",
    "background: white;": "background: #151b23;",
    "background: #e9f2ff;": "background: #152b44;",
    "color: #12395f;": "color: #b9dcff;",
    "color: #245f9f;": "color: #9dccff;",
    "color: #09673b;": "color: #78e5aa;",
    "color: #27313d;": "color: #d7dee8;",
    "box-shadow: 0 1px 2px rgba(0,0,0,.04);": "box-shadow: 0 1px 3px rgba(0,0,0,.45);",
}

for old, new in replacements.items():
    text = text.replace(old, new)

text = text.replace(
    "One-file review view: forensic timing and copied local media previews in the same card.",
    "Dark-mode review view: forensic timing and copied local media previews in the same card.",
)

mobile_css = """

  @media (max-width: 760px) {
    body {
      font-size: 14px;
    }
    header {
      position: static;
      padding: 12px;
    }
    header h1 {
      font-size: 18px;
      line-height: 1.2;
    }
    header p {
      font-size: 13px;
    }
    main {
      padding: 10px;
    }
    .summary {
      grid-template-columns: 1fr;
      gap: 8px;
    }
    .summary-card {
      padding: 10px;
    }
    .summary-card strong {
      font-size: 21px;
    }
    .note {
      padding: 10px;
      margin-bottom: 10px;
    }
    h2 {
      font-size: 18px;
      margin-top: 18px;
    }
    .jump {
      gap: 6px;
    }
    .jump a {
      padding: 6px 8px;
      font-size: 13px;
    }
    .event-card {
      margin: 10px 0;
      border-radius: 6px;
    }
    .event-head {
      padding: 10px;
    }
    .rank {
      min-width: 34px;
      padding: 4px 6px;
    }
    h3 {
      font-size: 16px;
      line-height: 1.25;
    }
    .category {
      font-size: 12px;
      line-height: 1.25;
    }
    .event-layout {
      display: flex;
      flex-direction: column;
    }
    .media-pane {
      order: -1;
      padding: 8px;
      border-bottom: 1px solid var(--line);
    }
    .image-link img {
      max-height: 72vh;
      object-fit: contain;
    }
    .pdf-preview object {
      height: 72vh;
    }
    .event-text {
      border-right: 0;
    }
    .timeline-strip {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 7px;
      padding: 10px;
    }
    .timeline-strip > div {
      min-width: 0;
    }
    .pill, .time, .contact {
      max-width: 100%;
      overflow-wrap: anywhere;
      font-size: 12px;
    }
    .description {
      padding: 10px;
      font-size: 14px;
      max-height: 180px;
      overflow: auto;
    }
    .grid {
      grid-template-columns: 1fr;
      gap: 7px;
      padding: 10px;
    }
    .field {
      padding: 7px;
    }
    .field-label {
      font-size: 11px;
    }
    details {
      padding: 0 10px 10px;
    }
    summary {
      padding: 10px 0;
    }
    .technical {
      grid-template-columns: 1fr;
    }
    .expanded-media img {
      max-height: none;
      width: 100%;
    }
    .expanded-media object {
      height: 80vh;
    }
  }
"""

text = text.replace("</style>", mobile_css + "\n</style>")

DARK.write_text(text, encoding="utf-8")
print(str(DARK))
