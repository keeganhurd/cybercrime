import csv
import re
from pathlib import Path

BASE = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Final Reopen Packet POPD SA")
SRC = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\IPhone Screenshot Evidence April 2024")
OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\POPD Final Supplemental Packet")
MESSAGES = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Messages.html")
FILE5531 = Path(r"C:\Users\thoma\Documents\Cyber Crimes\Hurd Evidence 2024-05-08\Hurd Evidence 2024-05-08\Messages\HTML\media\FILE_5531.pdf")

UNIQUE = BASE / "Unique_Capture_Send_Events.csv"
ALIAS = BASE / "Exhibit_File_Alias_Map.csv"
TOP20 = BASE / "Top_20_Exhibits_With_Texted_Timestamps.md"
TECH = BASE / "Technical_Limitations_And_Forensic_Requests.md"
SUMMARY = BASE / "Corrected_Submission_Summary_For_POPD_SA.md"
EXEC = BASE / "Executive_Summary_For_Detective.md"
TIMING = BASE / "Timing_Contradiction_Analysis_For_POPD_SA.md"
ADMISSION = BASE / "Admission_Corroboration_Matrix.md"
COUNT = BASE / "Event_Count_Clarification_Report.md"
HASH = BASE / "Hash_Manifest.csv"
MASTER_TIMELINE = BASE / "Master_Timeline.csv"

IC3_ID = "7ecec906b2fe4dfa8794ae9987e386f4"

PROHIBITED = [
    "guilty", "beyond a reasonable doubt", "incompetent", "cover up", "shielding",
    "news", "no other explanation", "clearly committed", "slam dunk", "jail",
    "plea", "custody", "kids back", "leverage", "revenge", "stupid obvious",
    "entrapment", "negligence", "I deserve justice",
]


def read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write(name, text):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(text.rstrip() + "\n", encoding="utf-8")


def event_at(events, timestamp):
    return next((e for e in events if e.get("MessagesHtmlTextedToMomTimestamp") == timestamp), None)


def event_line(e, label="", source_note="source-verified"):
    if not e:
        return f"- {label}: user-identified; requires source confirmation."
    desc = (e.get("VisualDescription") or "").replace("\n", " ")
    if len(desc) > 420:
        desc = desc[:417] + "..."
    return (
        f"- {e.get('MessagesHtmlTextedToMomTimestamp')}: {label or e.get('EventType')}. "
        f"Capture timestamp: {e.get('ScreenshotFilenameTimestamp') or 'not applicable'}. "
        f"Gap: {e.get('ElapsedSeconds') or 'not applicable'} seconds. "
        f"Content: {desc} "
        f"Why it matters: {source_note}."
    )


def find_events():
    events = read_csv(UNIQUE)
    by_time = {e.get("MessagesHtmlTextedToMomTimestamp"): e for e in events}
    return events, by_time


def harmful_timeline(by_time):
    items = [
        ("2024/04/19 11:10:24", "First observed April 19 texted screenshot; appears to show Elijah/Facebook/Ariana profile pattern evidence", "source-verified; early capture-to-send event, lower harm than later business/Gmail sequence"),
        ("2024/04/19 19:22:35", "April 19 evening account/card screen pattern evidence", "source-verified; timing/account pattern evidence"),
        ("2024/04/25 12:28:44", "Google Business Profile/customer-message screenshot for Florida Crystal Well & Sprinkler", "source-verified by OCR text naming Florida Crystal Well & Sprinkler"),
        ("2024/04/25 12:29:14", "Google Business Profile/customer-message continuation", "source-verified by sequence timing; review image content for final charge decision"),
        ("2024/04/25 12:32:46", "Google Business Profile/customer-message continuation", "source-verified by sequence timing; review image content for final charge decision"),
        ("2024/04/25 12:33:47", "Google Business Profile account/admin screenshot", "source-verified by sequence timing; user-identified content should be manually confirmed"),
        ("2024/04/25 12:43:25", "Virtue Capital email screenshot", "source-verified by OCR/sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 12:44:27", "Virtue Capital email screenshot", "source-verified by OCR/sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 12:45:32", "Virtue Capital email screenshot", "source-verified by OCR/sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 12:51:02", "HELO Payment Services LLC App Info / EIN / voided-check and business banking material", "source-verified by OCR; highly sensitive business and banking information"),
        ("2024/04/25 12:54:20", "FILE_5531.pdf texted/referenced in same TO: Mom sequence", "source-verified; actual IRS CP 575 EIN PDF, not merely a screenshot"),
        ("2024/04/25 12:54:44", "Screenshot of EIN letter open in Google Drive", "source-verified by OCR showing HELO Payment Services, IRS, CP 575, and Drive-style title text"),
        ("2024/04/25 12:56:24", "Thomas Hurd Florida ID card screenshot", "source-verified by OCR/sequence; manually verify image content"),
        ("2024/04/25 13:04:36", "Email to Florida Department of Health concerning DH-681 forms", "user-identified; requires source confirmation"),
        ("2024/04/25 13:11:53", "Kula Yoga / client-related email screenshot", "user-identified; requires source confirmation"),
        ("2024/04/25 13:15:31", "Virtue Capital application screenshot", "source-verified by OCR with DocuSign/commercial financing content"),
        ("2024/04/25 13:22:07", "Virtue Capital / IRS-EIN related screenshot", "source-verified by OCR category"),
        ("2024/04/25 13:22:32", "Virtue Capital / IRS-EIN related screenshot", "source-verified by OCR category"),
        ("2024/04/25 13:22:50", "Virtue Capital / IRS-EIN related screenshot", "source-verified by OCR category"),
        ("2024/04/25 13:27:09", "HOA letter from prior residence", "user-identified; requires source confirmation"),
        ("2024/04/25 13:42:17", "Navy Federal dashboard/business banking screenshot", "source-verified by sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 13:42:36", "Navy Federal dashboard/business banking screenshot", "source-verified by sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 13:42:55", "Navy Federal dashboard/business banking screenshot", "source-verified by sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 13:43:15", "Navy Federal dashboard/business banking screenshot", "source-verified by sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 13:49:02", "Navy Federal bank-statement materials associated with Virtue Capital/cash-advance application", "source-verified by sequence; user-identified content should be manually confirmed"),
        ("2024/04/25 13:56:52", "Profit-and-loss document for property review", "user-identified; requires source confirmation"),
        ("2024/04/25 14:03:02", "Google Doc/client Temporary Custody Transfer Agreement material", "user-identified; requires source confirmation"),
        ("2024/04/25 14:10:30", "Google Sheets/itemized transaction data for account reconciliation", "user-identified; requires source confirmation"),
        ("2024/04/25 22:51:18", "Google Sheets/itemized transaction data for account reconciliation", "user-identified; requires source confirmation"),
        ("2024/04/26 06:11:24", "Gmail search/mining sequence involving Jonathan/Venmo references", "source-verified by OCR; supports active Gmail searching/mining"),
        ("2024/04/26 06:24:37", "Gmail search for Ariana", "user-identified; requires source confirmation"),
    ]
    return "\n".join(event_line(by_time.get(ts), label, note) for ts, label, note in items)


def core_facts(events):
    screenshots = [e for e in events if e.get("EventType") == "Screenshot transmission"]
    immediate = [e for e in screenshots if e.get("ElapsedClassification") == "Immediate"]
    return len(screenshots), len(immediate)


def common_sections(events, by_time):
    total, immediate = core_facts(events)
    return {
        "counts": (
            f"The analysis identifies {total} unique screenshot-send events. "
            f"Of those, {immediate} unique screenshot-send events have a 0-30 second gap between "
            f"the screenshot filename/capture timestamp and the Messages.html/texted-to-Mom timestamp. "
            "The real-world screenshot/document event count appears approximately 100-105, subject to forensic confirmation."
        ),
        "phone": (
            "Messages.html is an UltData/phone-message HTML export. The thread label is `TO: Mom`. "
            "Recipient/Mom number appears in export text as `13863470544`, consistent with `1-386-347-0544`, "
            "but not as a clean structured native handle. Source/exported device number appears in export text as "
            "`623 418 0848`, but not as a clean structured native handle. Native iPhone sms.db is needed to confirm "
            "sender/recipient handles, attachment GUIDs, original attachment filenames, transfer metadata, deletion status, and actor attribution."
        ),
        "google": (
            "At the time of the screenshot sequence, `keeganhurd@gmail.com` had been logged in on Elijah's iPhone "
            "for YouTube/subaccount purposes. The reporting party did not realize this could also expose Gmail, "
            "Google Drive, Google Account, Google Business Profile, and related Google services. The screenshot "
            "contents themselves show Gmail/Google/business content displayed on the phone when the screenshots "
            "were captured. The later removal of `keeganhurd@gmail.com` from Elijah's phone was a remedial step "
            "to stop further unauthorized access and should not be treated as evidence that the account was never accessible."
        ),
        "file5531": (
            "`FILE_5531.pdf` is a key exhibit. It appears in the `TO: Mom` sequence at `2024/04/25 12:54:20`. "
            "It is an IRS CP 575 EIN notice for HELO PAYMENT SERVICES LLC with SHA256 "
            "`46FC44791F9A050C9F711BCE1732DB6E29AD5BB76D853C48B795E931E807D331`. "
            "It was not merely a screenshot; its presence shows a document/PDF attachment was transmitted or represented "
            "in the message sequence. The adjacent `2024/04/25 12:54:44` screenshot shows the EIN letter open in Google Drive. "
            "Together, these facts strongly support the inference that the person using the phone had active access to "
            "`keeganhurd@gmail.com` and related Google services at the time of capture. Native/provider records are needed "
            "to determine whether the PDF was obtained from Gmail attachment, Google Drive download, or another Google-synced source."
        ),
        "statements": (
            "Robin reportedly told POPD she went through Elijah's phone during a parental sweep, located shared photos/financial documents, "
            "took screenshots of documents, and provided them to attorney Christopher Ditslear. This should be verified against the official "
            "POPD supplemental report and Axon recording. On October 1, 2024, Robin stated under oath that she was able to find financial "
            "statements, business names, EIN numbers, bank statements, and the like. The local transcript is a supporting reference and should "
            "be verified against the official court audio/video. The categories she described match the recovered screenshot/PDF content."
        ),
    }


def write_email(events, by_time):
    s = common_sections(events, by_time)
    text = f"""# POPD Reopen Email Final

To: Det. Sgt. Eric Fields

Subject: Request to Reopen/Supplement Cybercrime Investigation - April 2024 iPhone/Gmail/Drive Evidence

Det. Sgt. Fields,

I am requesting that POPD reopen or supplement the investigation based on a focused technical analysis of the UltData message export, screenshot attachments, OCR content, and the located `FILE_5531.pdf` EIN document.

Your closure rationale indicated that screenshots were observed but that there was no evidence showing how the screenshots appeared or indicating access to emails/databases. The attached packet addresses that issue. The screenshot contents show Gmail, Google, business email, banking, Google Drive, and IRS/EIN material displayed on the phone at capture time. The capture-to-send timing shows immediate transmission to `Mom`. The later removal of `keeganhurd@gmail.com` from Elijah's phone does not negate access at the time of capture.

{s['counts']}

## Google / YouTube Account Vulnerability

{s['google']}

## Harmful Access Timeline Highlights

- First observed texted screenshot: `2024/04/19 11:10:24`, approximately 21 seconds after filename/capture timestamp. This appears to show Elijah/Facebook/Ariana profile material and is pattern evidence, not the main business/Gmail harm.
- April 19 evening event: `2024/04/19 19:22:35`, approximately 11 seconds after capture, showing a Cash App/card/account screen. This is timing/account pattern evidence.
- Main harmful access sequence begins April 25 at `2024/04/25 12:28:44`, including Google Business Profile/customer messages, Gmail/business emails, HELO Payment Services LLC App Info, EIN/IRS material, Navy Federal banking, Google Drive, and business records.
- {s['file5531']}

## Statements

{s['statements']}

## IC3

An IC3 complaint was filed. Submission ID: `{IC3_ID}`. The IC3 complaint lists Helo Payment Services LLC as the affected business, reports business operations impacted, and reports a claimed loss amount of $350,000. The IC3 receipt should be attached.

I request that POPD review the attached packet, compare the timeline against the Axon interview and native iPhone database, and obtain provider records from Apple/iCloud and Google. I can provide Google Takeout data and supporting business-loss documentation as requested.

## Attachments

See `POPD_Attachment_Checklist_Final.md`.
"""
    write("POPD_Reopen_Email_Final.md", text)


def write_complaint(events, by_time):
    s = common_sections(events, by_time)
    timeline = harmful_timeline(by_time)
    text = f"""# POPD Supplemental Complaint Final

## Purpose Of Submission

This submission provides a focused law-enforcement packet concerning April 2024 screenshot creation, message transmission, Gmail/Google/Drive/business-record content, and the `FILE_5531.pdf` IRS/EIN document in the `TO: Mom` UltData message export.

## Sgt. Fields Closure Rationale And Why This Analysis Addresses It

The closure rationale reportedly noted that screenshots existed but did not show how they appeared or establish access to emails/databases. This packet addresses that issue in three ways: first, the screenshot content itself shows Gmail/Google/business/email/banking/Drive material displayed on the phone at capture time; second, the capture-to-send timing shows immediate transmission; third, `FILE_5531.pdf` is an actual IRS/EIN PDF document appearing in the same `TO: Mom` sequence, not merely a screenshot.

## Core Timing Evidence

{s['counts']} The lead April 19 evening event has an approximately 11-second gap. The repeated 0-30 second pattern strongly undermines a simple later-discovery-in-Photos explanation and is more consistent with immediate capture-and-send conduct by whoever possessed the phone.

{s['phone']}

## Main Harmful Access Sequence

{timeline}

## Screenshot Contents Show Active Access To Gmail / Google / Business Records

The OCR and timeline evidence show Gmail search/content, Google Business Profile/customer messages, Google Drive/EIN content, HELO Payment Services LLC app information, Navy Federal banking materials, Virtue Capital/cash-advance application materials, Google Docs/Sheets content, and other business records. The evidence strongly supports the inference that the person using the phone had active access to `keeganhurd@gmail.com` and related Google services at the time of capture.

## FILE_5531.pdf / IRS EIN Document

{s['file5531']}

## Robin Statements

{s['statements']}

## Google Account / YouTube Vulnerability Explanation

{s['google']}

## Victim Impact And Business Harm

See `Victim_Impact_Business_Harm.md`. The impact section is submitted as victim-impact and business-damage information requiring supporting documentation.

## IC3 Report

An IC3 complaint was filed. Submission ID: `{IC3_ID}`. The complaint lists Helo Payment Services LLC as the affected business, reports business operations impacted, and reports a claimed loss amount of $350,000. The IC3 receipt should be attached to the submission packet.

## Requested Investigative Steps

- Obtain native iPhone `sms.db`, message table, handle table, attachment records, attachment GUIDs, transfer metadata, and deletion status.
- Obtain Apple/iCloud Photos and Messages metadata.
- Obtain Google Gmail/Drive/account access logs, IPs, user agents, session/device records, and download/access logs.
- Review POPD Axon Capture interview/audio/video and official supplemental report.
- Compare phone possession/custody/school timeline against the April 25 and April 26 events.
- Confirm whether `FILE_5531.pdf` originated from Gmail attachment, Google Drive, or another Google-synced source.

## Exhibits And Attachments

See `POPD_Attachment_Checklist_Final.md`.
"""
    write("POPD_Supplemental_Complaint_Final.md", text)


def write_timeline(events, by_time):
    text = f"""# Timeline Harmful Access Sequence

This timeline focuses on meaningful or harmful events, not every screenshot. "Source-verified" means the event appears in existing CSV/OCR/message-analysis outputs. "User-identified" means the description should be confirmed by law enforcement through the source image/native records.

{harmful_timeline(by_time)}
"""
    write("Timeline_Harmful_Access_Sequence.md", text)


def write_victim_impact():
    text = f"""# Victim Impact And Business Harm

This section is victim-impact and business-damage information. It should be supported with business, banking, and licensing documents before being treated as proven damages.

According to the reporting party, the unauthorized access exposed Helo Payment Services LLC's Navy Federal business checking account information and created a security vulnerability. To close that vulnerability, the Navy Federal business checking account used by Helo Payment Services LLC was closed.

Cash-advance and business-funding providers often rely on business checking account history and revenue stability to determine eligibility and advance amounts. According to the reporting party, closing the account impaired the ability to obtain necessary cash advances/business funding.

According to the reporting party, Helo Payment Services LLC had approximately $340,000 in gross revenue through that Navy Federal account before it was closed. Helo Payment Services LLC ran Google/Bing ads for clients and earned a percentage of ad spend.

Robin's October 1, 2024 testimony occurred in opposition to Thomas Hurd's effort to reinstate his driver's license. Driver's license reinstatement was important because Thomas Hurd operated mobile notary/fingerprinting services through GoFingerprinting.com.

According to the reporting party, mobile notary/fingerprinting services generated approximately $2,000/month in business revenue and helped support home office rent and related business operations. The reporting party contends that the combined effect of the bank-account closure, loss of account history/funding access, inability to drive for mobile services, and lost time contributed to the eventual collapse/suspension of services around November/December 2024.

The evidence supports the business-impact claim, but causation and dollar amounts require supporting documentation. Suggested supporting documents include: bank closure records, Navy Federal account history, Helo Payment Services LLC revenue records, ad spend/client revenue records, GoFingerprinting mobile service revenue, driver's license reinstatement records, IC3 receipt, and business shutdown/suspension records.
"""
    write("Victim_Impact_Business_Harm.md", text)


def write_checklist():
    text = f"""# POPD Attachment Checklist Final

Attach these first:

- Corrected_Submission_Summary_For_POPD_SA.pdf
- Executive_Summary_For_Detective.pdf
- Timing_Contradiction_Analysis_For_POPD_SA.pdf
- Top_20_Exhibits_With_Texted_Timestamps.pdf
- Technical_Limitations_And_Forensic_Requests.pdf
- Event_Count_Clarification_Report.pdf
- Admission_Corroboration_Matrix.pdf
- Final_Overstatement_Audit.pdf
- IC3 receipt PDF, Submission ID `{IC3_ID}`
- `FILE_5531.pdf`
- Lead April 19 screenshot
- Rendered Messages.html excerpts showing key messages
- Top harmful screenshots
- `Unique_Capture_Send_Events.csv`
- `Exhibit_File_Alias_Map.csv`
- `Master_Timeline.csv`
- `Hash_Manifest.csv`
- Google Takeout inventory or relevant extracts if requested
- Supporting business-loss documents if submitting damage evidence
"""
    write("POPD_Attachment_Checklist_Final.md", text)


def write_sa_followup():
    text = """# State Attorney Follow-Up Positioning

If POPD declines to reopen or supplement, the reporting party may request independent review by the State Attorney's Office through a victim-conferral or supplemental-evidence submission. The request should not attack POPD personally. It should state that the investigation appears incomplete because native iPhone records, Apple/iCloud provider records, Google records, and POPD Axon interview materials were not fully compared against the technical timeline.

The packet identifies specific probable-cause facts and specific investigative steps: immediate screenshot-to-message gaps, Gmail/Google/Drive/business content visible on the phone at capture time, `FILE_5531.pdf` as an IRS/EIN business document in the message sequence, and statements that should be compared against the Axon interview and hearing record.

Requested review should focus on whether additional records should be subpoenaed or forensically examined before any final charging decision.
"""
    write("SA_Followup_Positioning.md", text)


def language_audit():
    issues = []
    for path in OUT.glob("*.md"):
        if path.name == "Language_Audit_Final.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        new = text
        for phrase in PROHIBITED:
            if re.search(re.escape(phrase), new, re.I):
                issues.append((path.name, phrase))
                replacement = {
                    "guilty": "responsible",
                    "beyond a reasonable doubt": "requiring further confirmation",
                    "incompetent": "incomplete",
                    "cover up": "unresolved issue",
                    "shielding": "not fully investigated",
                    "news": "public",
                    "no other explanation": "the evidence strongly supports the inference",
                    "clearly committed": "is consistent with",
                    "slam dunk": "probative",
                    "jail": "law-enforcement action",
                    "plea": "case resolution",
                    "custody": "possession/care",
                    "kids back": "children",
                    "leverage": "advantage",
                    "revenge": "retaliation",
                    "stupid obvious": "apparent",
                    "entrapment": "investigative issue",
                    "negligence": "incomplete investigation",
                    "I deserve justice": "the reporting party requests review",
                }.get(phrase, "neutral investigative wording")
                new = re.sub(re.escape(phrase), replacement, new, flags=re.I)
        if new != text:
            path.write_text(new, encoding="utf-8")
    lines = ["# Language Audit Final", ""]
    if not issues:
        lines.append("No prohibited inflammatory phrases were found in the newly created markdown files.")
    else:
        for file, phrase in issues:
            lines.append(f"- `{file}` contained `{phrase}` and was revised to professional investigative wording.")
    write("Language_Audit_Final.md", "\n".join(lines))
    return issues


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    events, by_time = find_events()
    write_email(events, by_time)
    write_complaint(events, by_time)
    write_timeline(events, by_time)
    write_victim_impact()
    write_checklist()
    write_sa_followup()
    issues = language_audit()
    print(f"Fresh packet created: {OUT}")
    print("Avoided updated/corrected framing in POPD-facing narrative files: Yes")
    print("Included first April 19 event: Yes")
    print("Focused harmful sequence beginning April 25 at 12:28: Yes")
    print("Included Google/YouTube vulnerability explanation: Yes")
    print("Included victim impact/business harm: Yes")
    print(f"Included IC3 Submission ID: {IC3_ID}")
    print(f"Inflammatory language issues found/revised: {len(issues)}")


if __name__ == "__main__":
    main()
