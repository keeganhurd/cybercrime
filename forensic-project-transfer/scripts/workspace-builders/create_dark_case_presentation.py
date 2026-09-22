import re
import shutil
from pathlib import Path


SRC = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Case_Presentation")
DST = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Case_Presentation_Dark")

DARK_CSS = """
<style>
:root{--ink:#e8eef8;--muted:#aab7c8;--line:#334155;--bg:#0b1020;--panel:#111827;--panel2:#0f172a;--gmail:#143260;--drive:#123b28;--business:#32205f;--search:#563111;--corr:#5c1717;--warn:#45370a;--accent:#60a5fa;}
*{box-sizing:border-box} body{margin:0;background:linear-gradient(180deg,#070b16 0%,var(--bg) 180px);color:var(--ink);font:18px/1.5 Arial,Helvetica,sans-serif}
header{background:#030712;color:white;padding:28px 36px;border-bottom:1px solid #1f2937} header h1{margin:0 0 6px;font-size:34px} header p{margin:0;color:#cbd5e1}
main{max-width:1320px;margin:0 auto;padding:24px 28px 60px}
nav{display:flex;flex-wrap:wrap;gap:8px;background:#0f172a;padding:10px 28px;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10}
nav a{background:#111827;border:1px solid var(--line);border-radius:8px;color:#e8eef8;text-decoration:none;padding:8px 12px;font-weight:700}
nav a:hover{background:#1e293b;border-color:#60a5fa}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px;margin:16px 0;box-shadow:0 12px 30px rgba(0,0,0,.18)}
.summary{font-size:21px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.metric{border-left:8px solid #60a5fa;background:var(--panel);padding:14px 16px;border-radius:8px;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.metric b{display:block;font-size:30px;color:#f8fafc}.muted{color:var(--muted)} .small{font-size:14px}.mono{font-family:Consolas,Menlo,monospace}
a{color:#93c5fd} a:visited{color:#c4b5fd}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);font-size:16px} th{position:sticky;top:57px;background:#020617;color:white;text-align:left;padding:10px;z-index:5}td{border-top:1px solid var(--line);padding:10px;vertical-align:top}
tr:nth-child(even){background:#0f172a}.pill{display:inline-block;border-radius:999px;padding:4px 9px;font-size:13px;font-weight:800;margin:2px;background:#263244;color:#e8eef8;border:1px solid rgba(255,255,255,.08)}
.gmail{background:var(--gmail)}.drive{background:var(--drive)}.business{background:var(--business)}.search{background:var(--search)}.corr{background:var(--corr)}.important{outline:3px solid #f59e0b}
.event{border-left:10px solid #64748b;padding:14px 16px;margin:12px 0;background:var(--panel);border-radius:8px;border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.event.gmail{border-left-color:#3b82f6}.event.drive{border-left-color:#22c55e}.event.business{border-left-color:#a78bfa}.event.search{border-left-color:#f97316}.event.corr{border-left-color:#ef4444}
.time{font-size:22px;font-weight:800;color:#f8fafc}.desc{font-size:18px}.src{font-size:13px;color:#b6c2d2;word-break:break-all}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:18px}.shot{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}.shot img{width:100%;display:block;background:#05070d;max-height:520px;object-fit:contain}.shot object{width:100%;height:520px;background:#111827}
.shot .body{padding:14px}.box{border:2px solid #f97316;background:#1f160b;border-radius:12px;padding:16px;margin:18px 0}.redbox{border-color:#ef4444;background:#240f12}.warn{background:var(--warn);border-left:8px solid #f59e0b;padding:14px;border-radius:8px}
code,.mono{background:#020617;border:1px solid #1f2937;border-radius:5px;padding:1px 4px;color:#dbeafe}
@media(max-width:760px){body{font-size:16px}header{padding:22px}main{padding:16px}th{position:static}.gallery{grid-template-columns:1fr}table{font-size:14px}.time{font-size:19px}}
</style>
"""


def main():
    if not SRC.exists():
        raise SystemExit(f"Source folder not found: {SRC}")
    DST.mkdir(parents=True, exist_ok=True)
    images_src = SRC / "Images"
    images_dst = DST / "Images"
    if images_src.exists():
        images_dst.mkdir(parents=True, exist_ok=True)
        for item in images_src.iterdir():
            if item.is_file():
                shutil.copy2(item, images_dst / item.name)

    for src_html in SRC.glob("*.html"):
        text = src_html.read_text(encoding="utf-8")
        text = re.sub(r"<style>.*?</style>", DARK_CSS, text, count=1, flags=re.S)
        text = text.replace("<title>", "<title>Dark - ", 1)
        dst_html = DST / src_html.name
        dst_html.write_text(text, encoding="utf-8")

    summary = SRC / "presentation_summary.txt"
    if summary.exists():
        shutil.copy2(summary, DST / summary.name)
    print(f"Created dark mode case presentation: {DST}")


if __name__ == "__main__":
    main()
