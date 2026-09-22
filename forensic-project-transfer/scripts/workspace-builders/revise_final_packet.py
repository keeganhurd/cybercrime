import csv
import re
import sys
from pathlib import Path

FINAL = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA")
MASTER = FINAL / "Master_Exhibit_Index.csv"

POPD_EXCERPT = (
    "Robin reportedly stated she went through Elijah's phone during a parental sweep, "
    "located shared photos/financial documents, screenshoted documents, and provided them "
    "to attorney Christopher Ditslear. This excerpt is user-provided and requires verification "
    "against the official POPD supplemental report and Axon recording."
)

OCT1_STATEMENT = (
    "In the October 1, 2024 hearing transcript, Robin stated she was able to find "
    "financial statements, business names, EIN numbers in Thomas Hurd's name, and bank "
    "statements and the like. This is based on the local unofficial SRT transcript and "
    "should be verified against the official court record/audio."
)

PHONE_NOTE = (
    "Recipient/Mom number visible in export text as 13863470544, consistent with "
    "1-386-347-0544. Source/exported device number visible in export text as "
    "623 418 0848. These are not exposed in Messages.html as clean structured "
    "sender/recipient handles."
)

BANNED = [
    "Keegan should",
    "Father should",
    "Petitioner should",
    "Victim should",
    "TODO",
    "note to Keegan",
    "I think",
    "you should",
    "submit this",
    "ask them",
    "obviously guilty",
    "beyond a reasonable doubt",
    "guilty",
]


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write(path, text):
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def top20(master):
    def score(r):
        if r.get("ScreenshotFilenameTimestamp") == "2024-04-19 19:22:24":
            return 100000
        if r.get("DisplayFileName") == "FILE_5531.pdf":
            return 99000
        cats = r.get("OCRCategory", "")
        s = 0
        for term, pts in [
            ("IRS/EIN", 5000),
            ("Gmail", 4000),
            ("Google Account", 3800),
            ("Google Drive", 3700),
            ("Navy Federal", 3500),
            ("Bank Statement", 3300),
            ("Financial Statement", 3200),
            ("Business Record", 3000),
            ("Helo Payment Services", 2900),
        ]:
            if term in cats:
                s += pts
        if r.get("ElapsedClassification") == "Immediate":
            s += 1000
        try:
            elapsed = int(r.get("ElapsedSeconds") or "9999")
            s += max(0, 500 - elapsed)
        except ValueError:
            pass
        return s
    out = []
    seen = set()
    for r in sorted(master, key=score, reverse=True):
        key = r.get("SHA256") or r.get("DisplayFileName")
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
        if len(out) == 20:
            break
    return out


def field_block(r):
    return f"""- Screenshot filename timestamp / capture timestamp: {r.get('ScreenshotFilenameTimestamp') or 'Not applicable'}
- Messages.html timestamp / texted-to-Mom timestamp: {r.get('MessagesHtmlTimestamp') or 'Not available'}
- Elapsed time from filename timestamp to texted timestamp: {r.get('ElapsedSeconds') or 'Not applicable'}
- Elapsed classification: {r.get('ElapsedClassification') or 'Not applicable'}
- Conversation/contact: {r.get('ConversationOrContact') or 'Not available'}
- Recipient/contact: {r.get('ConversationOrContact') or 'Mom / not structurally confirmed'}
- Recipient phone if visible: {r.get('RecipientPhoneIfShown') or PHONE_NOTE}
- Source/exported device phone if visible: {r.get('SenderPhoneIfShown') or PHONE_NOTE}
- Direction inference: {r.get('DirectionInference') or 'Not available'}
- HTML/media file name: {Path(r.get('MatchingHtmlMediaFile') or r.get('SourcePath') or '').name}
- Screenshot/photo source file name: {Path(r.get('MatchingPhotoFile') or r.get('SourcePath') or '').name}
- Cross-folder match: {('Yes' if r.get('MatchingHtmlMediaFile') and r.get('MatchingPhotoFile') else 'No or not applicable')}
- Sensitive content category: {r.get('SensitiveContentType') or r.get('OCRCategory') or 'None detected by OCR'}
- OCR/visual description: {r.get('VisualDescription') or 'Not available'}
- Why this exhibit matters: {r.get('WhyItMatters') or 'Not available'}
- Limitation / native confirmation needed: {r.get('Limitation') or 'Native iPhone database confirmation is required.'} {r.get('NativeConfirmationNeeded') or ''}"""


def write_top20(top):
    lines = ["# Top 20 Exhibits With Texted Timestamps", ""]
    for i, r in enumerate(top, 1):
        lines.append(f"## {i}. {r['ExhibitNumber']} - {r['DisplayFileName']}")
        lines.append("")
        lines.append(f"- File name: {r['DisplayFileName']}")
        lines.append(f"- File path: `{r['SourcePath']}`")
        lines.append(f"- Hash: `{r.get('SHA256')}`")
        lines.append(field_block(r))
        lines.append("")
    write(FINAL / "Top_20_Exhibits_With_Texted_Timestamps.md", "\n".join(lines))
    write(FINAL / "Top_20_Exhibits_Updated.md", "\n".join(lines))


def write_binders(master):
    lines = ["# Exhibit Binder", "", "Each exhibit separates screenshot/capture time from Messages.html/texted-to-Mom time. Direction is inferred from the HTML export and requires native iPhone database confirmation.", ""]
    for r in master:
        lines.append(f"## {r['ExhibitNumber']} - {r['DisplayFileName']}")
        lines.append("")
        lines.append(f"- File path: `{r['SourcePath']}`")
        lines.append(f"- SHA256: `{r.get('SHA256')}`")
        lines.append(field_block(r))
        lines.append("- What law enforcement should verify: " + (r.get("RecommendedInvestigatorAction") or "Verify through native extraction and provider records."))
        lines.append("")
    text = "\n".join(lines)
    write(FINAL / "Exhibit_Binder.md", text)
    write(FINAL / "Exhibit_Binder_NoImages.md", text)


def timing_section():
    return f"""## Timing Contradiction With Later-Discovery Explanation

Robin's reported POPD statement describes a parental sweep of Elijah's phone, later discovery of shared photos/financial documents, screenshoting documents, and providing them to attorney Christopher Ditslear. Her October 1, 2024 testimony states that she was able to find financial statements, business names, EIN numbers, bank statements, and the like.

The technical timeline creates a material timing issue with a simple later-discovery explanation. The lead screenshot filename timestamp is `2024-04-19 19:22:24`, and the Messages.html/texted-to-Mom timestamp is `2024/04/19 19:22:35`, an approximately 11-second gap. The packet verifies 97 screenshot-send events within 0-30 seconds.

This timing pattern strongly undermines a simple explanation that the images were merely discovered later in Photos. The repeated 0-30 second gaps are more consistent with immediate capture-and-send conduct by the person possessing the phone. Native iPhone database confirmation is still required for sender/recipient handles, attachment GUIDs, and actor attribution. POPD should compare this timeline against Robin's Axon interview and the native iPhone message database.
"""


def write_summary_files(master, top):
    sensitive_count = sum(1 for r in master if r.get("OCRCategory"))
    immediate_count = sum(1 for r in master if r.get("ElapsedClassification") == "Immediate")
    mapped_count = sum(1 for r in master if r.get("MatchingHtmlMediaFile") and r.get("MatchingPhotoFile"))
    lead = next(r for r in master if r.get("ScreenshotFilenameTimestamp") == "2024-04-19 19:22:24")

    write(FINAL / "Executive_Summary_For_Detective.md", f"""# Executive Summary For Detective

The lead exhibit is the April 19 screenshot with a filename/capture timestamp of `2024-04-19 19:22:24` and a Messages.html/texted-to-Mom timestamp of `2024/04/19 19:22:35`, an approximately 11-second gap. OCR detected on-screen time `7:22`, matching the filename/message minute. The exhibit is strongest for timing/immediate-send behavior, not Gmail/Drive/IRS content.

The packet verifies {immediate_count} exhibits with immediate 0-30 second gaps in the master index, representing the repeated immediate-send pattern already identified in the source analysis. OCR/manual classification identifies {sensitive_count} exhibits with sensitive categories, including Gmail, Google Drive, Google Account, IRS/EIN, bank/financial, and business-record indicators. {PHONE_NOTE}

`FILE_5531.pdf` appears in the `TO: Mom` sequence at `2024/04/25 12:54:20`, between screenshot messages at approximately 12:51:02 and 12:54:44. It is an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC.

{timing_section()}
""")

    write(FINAL / "Admission_Corroboration_Matrix.md", f"""# Admission Corroboration Matrix

## Timing Contradiction With Later-Discovery Explanation

| Statement/admission | Source | What she said | Matching exhibit(s) | Corroboration / contradiction | Caveat |
| --- | --- | --- | --- | --- | --- |
| Parental sweep / found shared photos and financial documents / screenshoted documents / gave them to attorney | Provided POPD excerpt requiring verification against official POPD report and Axon recording | {POPD_EXCERPT} | {lead['ExhibitNumber']} lead 11-second exhibit; FILE_5531.pdf; 97 immediate gaps; OCR-sensitive exhibits | This timing pattern strongly undermines a simple explanation that the images were merely discovered later in Photos. | Native iPhone database confirmation is required for sender/recipient handles, attachment GUIDs, and actor attribution. |
| Able to find financial statements, business names, EIN numbers, bank statements and the like | October 1, 2024 unofficial SRT transcript; verify against official court record/audio | {OCT1_STATEMENT} | FILE_5531.pdf; OCR exhibits showing IRS/EIN, Gmail, bank/financial/business categories | The categories described in testimony are present in the screenshot/PDF evidence. | The transcript does not prove the access method or actor identity by itself. |

POPD should compare this timeline against Robin's Axon interview and the native iPhone message database.
""")

    write(FINAL / "Timing_Contradiction_Analysis_For_POPD_SA.md", f"""# Timing Contradiction Analysis For POPD / State Attorney

## Bottom Line

The technical timeline strongly undermines a simple explanation that the images were merely discovered later in Photos. The lead screenshot was created, based on filename timestamp, at `2024-04-19 19:22:24` and appears in the `TO: Mom` thread at `2024/04/19 19:22:35`, approximately 11 seconds later. The packet verifies 97 screenshot-send events within 0-30 seconds in the source gap analysis. This pattern is more consistent with immediate capture-and-send conduct by the person possessing the phone than with later accidental discovery. Native iPhone database confirmation is still required.

## Robin's Reported POPD Statement

{POPD_EXCERPT}

This should be verified against the official POPD supplemental report and Axon Capture recording.

## Robin's October 1 Sworn Statement

{OCT1_STATEMENT}

The local transcript segment supports that the categories included financial statements, business names, EIN numbers, and bank statements. The official court record/audio should be obtained.

## Technical Timing Evidence

- Lead screenshot filename/capture timestamp: `2024-04-19 19:22:24`
- Lead Messages.html/texted-to-Mom timestamp: `2024/04/19 19:22:35`
- Lead elapsed gap: approximately 11 seconds
- Verified immediate 0-30 second gaps in source gap analysis: 97
- `TO: Mom` thread label: visible in export
- Recipient/Mom phone visible in export text: `13863470544`, consistent with `1-386-347-0544`
- Source/exported device phone visible in export text: `623 418 0848`
- Structured sender/recipient handles: not exposed in Messages.html; native database required

## Why 11 Seconds Matters

An 11-second gap between screenshot filename timestamp and texted-to-Mom timestamp is probative because it leaves little practical time for unrelated later discovery. It supports the inference that the person possessing the phone captured the image and transmitted it immediately.

## Why 97 Immediate Gaps Matter

One immediate gap could theoretically have an innocent explanation. A repeated pattern of 97 immediate 0-30 second gaps is materially different. The pattern is consistent with immediate capture-and-send conduct and strongly undermines a simple later-discovery-in-Photos explanation.

## Why FILE_5531.pdf Matters

`FILE_5531.pdf` appears in the April 25 `TO: Mom` sequence at `2024/04/25 12:54:20`. It is an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC. This confirms the sequence included an actual sensitive IRS/EIN business PDF, not only screenshots.

## What Is Strongly Supported

- The `TO: Mom` export contains rapid screenshot-to-message gaps.
- The lead gap is approximately 11 seconds.
- The pattern includes many immediate transmissions.
- Sensitive categories appear in OCR/PDF evidence.
- The POPD reported statement and October 1 testimony align with the categories seen in the evidence.

## What Still Requires Forensic Confirmation

- Who physically held the phone.
- Native sender/recipient handles.
- Attachment GUIDs and transfer metadata.
- Whether any images were derivative/exported/AirDropped copies.
- Apple/iCloud and Google provider records.

## Specific Investigative Requests

- Obtain and analyze native iPhone `sms.db`, handle tables, attachment records, transfer metadata, and deletion status.
- Obtain Apple/iCloud Photos and Messages metadata for April 19-26, 2024.
- Obtain Google Gmail/Drive/account access logs, IPs, user agents, and sessions.
- Obtain POPD Axon Capture interview/audio/video and official supplemental report.
- Compare the timing evidence against phone possession, custody, and school timeline records.
""")

    write(FINAL / "Found_Later_Explanation_Analysis_Final.md", timing_section())
    write(FINAL / "Evidence_Strength_Assessment_Final.md", f"""# Evidence Strength Assessment Final

## Strong Circumstantial Evidence

- Lead 11-second screenshot filename-to-message gap.
- 97 immediate 0-30 second gaps verified in the source gap analysis.
- {sensitive_count} master-index exhibits with OCR/manual sensitive categories.
- FILE_5531.pdf IRS/EIN document in the April 25 `TO: Mom` sequence.

## Corroborating Evidence

- Reported POPD statement, pending official verification.
- October 1 transcript segment identifying financial statements, business names, EIN numbers, and bank statements.
- Phone numbers visible in export text: `13863470544` and `623 418 0848`.

## Missing Proof

- Native iPhone sender/recipient handles.
- Attachment GUIDs and transfer metadata.
- Actor identity.
- Apple/iCloud and Google provider records.
""")

    write(FINAL / "POPD_Reopen_Request_Cover_Memo.md", f"""# POPD Reopen Request Cover Memo

This submission requests that Port Orange Police Department reopen or supplement the investigation based on organized technical timing evidence. The lead screenshot has a filename/capture timestamp of `2024-04-19 19:22:24` and a Messages.html/texted-to-Mom timestamp of `2024/04/19 19:22:35`, an approximately 11-second gap.

The packet verifies 97 immediate 0-30 second gaps in the source gap analysis, and `FILE_5531.pdf` appears in the April 25 `TO: Mom` sequence as an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC.

POPD should compare this timeline against Robin's Axon interview and the native iPhone message database. Native iPhone database confirmation is still required for sender/recipient handles, attachment GUIDs, and actor attribution.
""")

    write(FINAL / "Technical_Limitations_And_Forensic_Requests.md", f"""# Technical Limitations And Forensic Requests

- Messages.html is an UltData/phone-message HTML export. It supports direction inference but is not the native iPhone database.
- The thread label is `TO: Mom`.
- {PHONE_NOTE}
- Need native `sms.db`, handle table, message table, attachment table, attachment GUIDs, transfer metadata, and deletion status.
- Need Apple/iCloud Photos and Messages metadata.
- Need Google Gmail/Drive/account access logs, IPs, user agents, and sessions.
- Need POPD Axon interview/audio/video and official supplemental report.
- Need phone possession/custody/school timeline.
- Do not rely on filesystem created/modified times alone because derivative/export/AirDrop copies may exist.
""")

    write(FINAL / "MASTER_REOPEN_PACKET_README.md", f"""# Master Reopen Packet README

This final packet is a law-enforcement submission package for POPD and State Attorney review. It focuses on screenshot capture timestamps, Messages.html/texted-to-Mom timestamps, elapsed-time gaps, OCR-sensitive content, FILE_5531.pdf, and corroborating statements.

Investigators should use `Master_Exhibit_Index.csv`, `Top_20_Exhibits_With_Texted_Timestamps.md`, `Timing_Contradiction_Analysis_For_POPD_SA.md`, and `Technical_Limitations_And_Forensic_Requests.md` as the first review set.

The evidence supports the inference of immediate capture-and-send conduct but does not independently prove who physically held the phone. Native iPhone and provider confirmation is required.
""")


def audit_and_clean():
    issues = []
    md_files = list(FINAL.glob("*.md"))
    replacements = {
        "beyond a reasonable doubt": "requires further forensic confirmation",
        "obviously guilty": "the evidence supports the inference",
        "guilty": "responsible",
        "you should": "investigators should",
        "submit this": "provide this packet",
        "ask them": "request that investigators",
        "I think": "the evidence indicates",
        "Keegan should": "investigators should",
        "Father should": "investigators should",
        "Petitioner should": "investigators should",
        "Victim should": "investigators should",
        "TODO": "Follow-up",
        "note to Keegan": "investigative note",
    }
    for path in md_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        new_text = text
        for phrase in BANNED:
            if re.search(re.escape(phrase), new_text, re.I):
                issues.append({
                    "file": path.name,
                    "phrase": phrase,
                    "why": "Submission language should remain neutral and directed to law enforcement.",
                    "replacement": replacements.get(phrase, "neutral investigative wording"),
                })
                new_text = re.sub(re.escape(phrase), replacements.get(phrase, "neutral investigative wording"), new_text, flags=re.I)
        if new_text != text:
            path.write_text(new_text, encoding="utf-8")
    if issues:
        lines = ["# Submission Language Audit", ""]
        for issue in issues:
            lines.append(f"- File: `{issue['file']}`; phrase: `{issue['phrase']}`; why inappropriate: {issue['why']}; suggested/revised replacement: {issue['replacement']}")
        write(FINAL / "Submission_Language_Audit.md", "\n".join(lines))
    else:
        write(FINAL / "Submission_Language_Audit.md", "# Submission Language Audit\n\nNo inappropriate submission-language phrases from the requested search list were found after revision.")
    return issues


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    master = read_csv(MASTER)
    top = top20(master)
    write_top20(top)
    write_binders(master)
    write_summary_files(master, top)
    issues = audit_and_clean()
    print(f"Top 20 updated: {len(top)}")
    print(f"Binder exhibits updated: {len(master)}")
    print("Recipient phone included where visible: 386-347-0544 / 1-386-347-0544 as visible in export text")
    print("Source/exported device phone included where visible: 623-418-0848 as visible in export text")
    print("Timing_Contradiction_Analysis_For_POPD_SA.md created: Yes")
    print(f"Submission language issues found and revised: {len(issues)}")
    print("Strongest 5 exhibits after revision:")
    for r in top[:5]:
        print(f"- {r['ExhibitNumber']}: {r['DisplayFileName']} | capture={r.get('ScreenshotFilenameTimestamp') or 'n/a'} | texted={r.get('MessagesHtmlTimestamp') or 'n/a'} | elapsed={r.get('ElapsedSeconds') or 'n/a'}")


if __name__ == "__main__":
    main()
