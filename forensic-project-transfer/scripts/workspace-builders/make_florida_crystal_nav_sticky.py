from pathlib import Path

path = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Florida_Crystal_Well_Steve_Roberge_Evidence\index_revised.html")
text = path.read_text(encoding="utf-8")

text = text.replace(
    "    body { margin: 0; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.48; }",
    "    body { margin: 0; padding-top: 58px; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.48; }",
)
text = text.replace(
    "    nav { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }",
    "    nav { position: fixed; top: 0; left: 0; right: 0; z-index: 1000; display: flex; flex-wrap: wrap; gap: 8px; margin-top: 0; padding: 10px 24px; background: rgba(18, 23, 34, .97); border-bottom: 1px solid var(--line); box-shadow: 0 8px 22px rgba(0,0,0,.32); max-height: 36vh; overflow-y: auto; }",
)
text = text.replace(
    "      nav { display: none; }",
    "      body { padding-top: 0; }\n      nav { display: none; }",
)
text = text.replace(
    "      header { padding: 22px 14px; }",
    "      header { padding: 22px 14px; }\n      body { padding-top: 66px; }\n      nav { padding: 8px 12px; gap: 6px; }",
)

path.write_text(text, encoding="utf-8")
print(f"Updated sticky nav in {path}")
