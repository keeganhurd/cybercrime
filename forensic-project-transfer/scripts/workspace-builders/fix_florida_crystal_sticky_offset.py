from pathlib import Path


path = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Florida_Crystal_Well_Steve_Roberge_Evidence\index_revised.html")
text = path.read_text(encoding="utf-8")

text = text.replace(
    "    body { margin: 0; padding-top: 58px; font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.48; }",
    "    body { margin: 0; padding-top: calc(var(--sticky-nav-height, 72px) + 14px); font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.48; }",
)
text = text.replace(
    "      body { padding-top: 66px; }\n      nav { padding: 8px 12px; gap: 6px; }",
    "      body { padding-top: calc(var(--sticky-nav-height, 84px) + 14px); }\n      nav { padding: 8px 12px; gap: 6px; }",
)

script = """  <script>
    function updateStickyNavOffset() {
      const nav = document.querySelector('nav');
      if (!nav) return;
      document.documentElement.style.setProperty('--sticky-nav-height', nav.offsetHeight + 'px');
    }
    window.addEventListener('load', updateStickyNavOffset);
    window.addEventListener('resize', updateStickyNavOffset);
    updateStickyNavOffset();
  </script>
"""

if "function updateStickyNavOffset()" not in text:
    text = text.replace("</body>", script + "</body>")

path.write_text(text, encoding="utf-8")
print(f"Updated sticky nav offset in {path}")
