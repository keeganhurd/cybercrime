from pathlib import Path
import re


path = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs\Florida_Crystal_Well_Steve_Roberge_Evidence\index_revised.html")
text = path.read_text(encoding="utf-8")
original = text

# 1. Wording and name fixes.
text = text.replace("Independent Business-Owner Complaint", "Business Owner Complaint")
text = text.replace("Independent Business Owner Complaint", "Business Owner Complaint")
text = text.replace("Robin Colleen Hurd-Bedner", "Robin Colleen Bedner")
text = text.replace("Robin Hurd-Bedner", "Robin Colleen Bedner")
text = text.replace("Robin Colleen Hurd Bedner", "Robin Colleen Bedner")

# 2. Related POPD Case section: add a neutral coordination sentence.
old_related = """      POPD reviewed data recovered from the relevant phone<br>
      POPD obtained a recorded statement from Robin Colleen Bedner<br>
      This packet is limited to the seven Florida Crystal Well & Sprinkler items</p>"""
new_related = """      POPD reviewed data recovered from the relevant phone<br>
      POPD obtained a recorded statement from Robin Colleen Bedner<br>
      This packet is limited to the seven Florida Crystal Well & Sprinkler items</p>
      <p>The broader dataset and recorded statement are already in the possession of Port Orange Police Department, and Flagler County law enforcement may coordinate with POPD as appropriate.</p>"""
if old_related not in text:
    raise SystemExit("Related Investigation block not found")
text = text.replace(old_related, new_related)

# 3. Stronger technical conclusion: replace the soft Evidence Boundary paragraph.
old_boundary = """    <section>
      <h2>Evidence Boundary</h2>
      <p>The timing and account-linked records establish a fresh capture, backup, and transmission sequence. They do not alone identify the person physically operating the device. Actor identification should be evaluated from the total evidence, including device possession and control, the recipient telephone number, native iPhone records, Apple/iCloud records, Google account and Google Business Profile logs, POPD's recorded interview, and subsequent possession or use of the materials.</p>
    </section>"""
new_boundary = """    <section>
      <h2>Technical Conclusion and Evidence Boundary</h2>
      <p>The timing sequence (<span class="capture-value">capture</span> -&gt; <span class="backup-value">Google Photos backup within 0-1 second</span> -&gt; <span class="transmit-value">transmission within seconds</span>) strongly supports that the screenshots were taken on a device that was at that moment logged into or actively syncing with the Google account associated with <span class="account-value">keeganhurd@gmail.com</span>. Port Orange Police Department already possesses the forensic extraction of the iPhone that performed the capture, transmission, and backup sequence. The October 1, 2024 sworn statement by Robin Colleen Bedner that she was able to locate financial statements, business names, EIN numbers, and bank statements is consistent with the type of unauthorized access shown in these business records. Taken together, the timing, the account linkage, the transmission to <span class="transmit-value">386-347-0544</span>, and the sworn statement leave no other reasonable explanation for the sequence of events.</p>
      <p class="muted-note">This conclusion remains evidence-bound: final actor identification should be evaluated with native phone/provider records, device possession and control, recipient-number attribution, and recorded statements.</p>
    </section>"""
if old_boundary not in text:
    raise SystemExit("Evidence Boundary block not found")
text = text.replace(old_boundary, new_boundary)

# 4. Visual/readability improvements.
style_replacements = {
    "--capture: #ff9e64;": "--capture: #ff9e64;",
    "--backup: #9ece6a;": "--backup: #a6e85f;",
    "--transmit: #7dcfff;": "--transmit: #66d9ef;",
    "--delta: #e0af68;": "--delta: #ffd166;",
    "--technical: #73daca;": "--technical: #8be9fd;",
    ".capture-value { color: var(--capture); font-weight: 800; }": ".capture-value { color: var(--capture); font-weight: 950; }",
    ".backup-value { color: var(--backup); font-weight: 800; }": ".backup-value { color: var(--backup); font-weight: 950; }",
    ".transmit-value { color: var(--transmit); font-weight: 800; }": ".transmit-value { color: var(--transmit); font-weight: 950; }",
    ".delta-value { color: var(--delta); font-weight: 900; }": ".delta-value { color: var(--delta); font-weight: 950; background: rgba(255, 209, 102, .10); border: 1px solid rgba(255, 209, 102, .35); border-radius: 5px; padding: 1px 5px; display: inline-block; }",
    ".technical-value { color: var(--technical); }": ".technical-value { color: var(--technical); font-weight: 950; }",
    "th, td { padding: 9px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); }": "th, td { padding: 10px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); }",
    ".tier1-row td { border-top: 1px solid var(--entity); border-bottom: 1px solid var(--entity); background: #1a1b1f !important; }": ".tier1-row td { border-top: 2px solid var(--entity); border-bottom: 2px solid var(--entity); background: #1d2028 !important; font-weight: 800; }",
    ".badges span { background: #202b24; border: 1px solid #3e6747; color: var(--backup); padding: 5px 8px; border-radius: 999px; font-weight: 900; font-size: .78rem; }": ".badges span { background: #202b24; border: 1px solid #5c915f; color: var(--backup); padding: 6px 9px; border-radius: 999px; font-weight: 950; font-size: .82rem; }",
}
for old, new in style_replacements.items():
    if old in text:
        text = text.replace(old, new)

extra_css = """    .chain-focus .flow { border: 1px solid rgba(166, 232, 95, .35); border-radius: 9px; padding: 8px; background: rgba(166, 232, 95, .04); }
    #timeline td:first-child { font-size: 1.02rem; font-weight: 950; }
    .card.full { border-color: rgba(246, 193, 119, .55); }
"""
marker = "    @media print {\n"
if extra_css not in text:
    text = text.replace(marker, extra_css + marker)

# 5. Remove Affidavit section and its nav link.
text = text.replace('      <a href="#appendix-d">Appendix D</a>\n', "")
text = re.sub(r"\n    <section id=\"appendix-d\">.*?\n    </section>\n", "\n", text, flags=re.S)

# Ensure no unintended Hurd-Bedner remnants remain.
text = text.replace("Robin Colleen Hurd-Bedner", "Robin Colleen Bedner")
text = text.replace("Robin Hurd-Bedner", "Robin Colleen Bedner")

if text == original:
    raise SystemExit("No changes made")

path.write_text(text, encoding="utf-8")
print(f"Updated {path}")
