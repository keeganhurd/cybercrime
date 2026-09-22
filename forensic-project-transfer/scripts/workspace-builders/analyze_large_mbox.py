import csv
import email
import email.policy
import email.utils
import re
from pathlib import Path
from datetime import datetime, timezone


MBOX = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\All mail Including Spam and Trash-002.mbox")
OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")
START = datetime(2024, 4, 19, 0, 0, 0)
END = datetime(2024, 4, 26, 23, 59, 59)

TERMS = [
    "FILE_5531.pdf", "HELO Payment Services LLC EIN.pdf", "HELO Payment Services",
    "Helo", "CP 575", "147C", "IRS", "EIN", "Navy Federal", "bank statement",
    "statement", "merchant", "Stripe", "Authorize", "Payanywhere",
    "GoFingerprinting", "Go Fingerprinting", "Virtue Capital", "LCF Group",
    "DocuSign", "Jonathan", "Braese", "Breas", "Ariana", "Gavin", "Venmo",
    "Drive", "Google Drive", "docs.google.com", "drive.google.com",
    "keeganhurd@gmail.com", "Robin", "Elijah", "Mom",
]

TERM_PATTERNS = [(t, re.compile(re.escape(t), re.I)) for t in TERMS]
ATTACH_RE = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";\r\n]+)', re.I)


def decode_header_value(value):
    if not value:
        return ""
    try:
        return str(email.headerregistry.AddressHeader) if False else str(email.header.decode_header(value))
    except Exception:
        pass
    try:
        parts = email.header.decode_header(value)
        out = []
        for part, enc in parts:
            if isinstance(part, bytes):
                out.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(part)
        return "".join(out)
    except Exception:
        return value


def parse_headers(header_bytes):
    raw = header_bytes.decode("utf-8", errors="replace")
    try:
        msg = email.message_from_string(raw, policy=email.policy.default)
    except Exception:
        msg = {}
    date_raw = msg.get("Date", "") if hasattr(msg, "get") else ""
    parsed = None
    try:
        parsed = email.utils.parsedate_to_datetime(date_raw)
        if parsed and parsed.tzinfo:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception:
        parsed = None
    subject = decode_header_value(msg.get("Subject", "")) if hasattr(msg, "get") else ""
    from_ = decode_header_value(msg.get("From", "")) if hasattr(msg, "get") else ""
    to = decode_header_value(msg.get("To", "")) if hasattr(msg, "get") else ""
    msgid = msg.get("Message-ID", "") if hasattr(msg, "get") else ""
    labels = msg.get("X-Gmail-Labels", "") if hasattr(msg, "get") else ""
    return {
        "date_raw": date_raw,
        "date": parsed,
        "subject": subject,
        "from": from_,
        "to": to,
        "message_id": msgid,
        "labels": labels,
        "headers_text": raw,
    }


def in_window(date):
    return bool(date and START <= date <= END)


def find_terms(text):
    return [term for term, pat in TERM_PATTERNS if pat.search(text)]


def short_snippet(text, term):
    match = re.search(re.escape(term), text, flags=re.I)
    if not match:
        return ""
    start = max(0, match.start() - 160)
    end = min(len(text), match.end() + 220)
    snippet = text[start:end]
    snippet = re.sub(r"\s+", " ", snippet).strip()
    return snippet[:500]


def format_dt(date):
    return date.isoformat(sep=" ", timespec="seconds") if date else ""


def write_csv(path, rows, headers):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def analyze():
    OUT.mkdir(parents=True, exist_ok=True)
    if not MBOX.exists():
        raise SystemExit(f"Missing MBOX: {MBOX}")

    message_count = 0
    window_count = 0
    window_hits = []
    keyword_hits = []
    attachment_hits = []
    important_examples = []

    current_header = bytearray()
    header_done = False
    current = None
    body_hit_terms = set()
    body_snippets = {}
    attachments = set()

    def finish_message():
        nonlocal current, body_hit_terms, body_snippets, attachments, window_count
        if not current:
            return
        terms = set(find_terms(" ".join([
            current.get("subject", ""), current.get("from", ""), current.get("to", ""),
            current.get("headers_text", ""), " ".join(attachments),
        ])))
        terms.update(body_hit_terms)
        is_window = in_window(current.get("date"))
        if is_window:
            window_count += 1
        relevant = bool(terms) and (is_window or any(t.lower() in {"file_5531.pdf", "helo payment services", "cp 575", "147c", "ein", "navy federal", "virtue capital", "docusign"} for t in terms))
        if is_window:
            window_hits.append({
                "TimestampUTC": format_dt(current.get("date")),
                "Subject": current.get("subject", ""),
                "From": current.get("from", ""),
                "To": current.get("to", ""),
                "MessageID": current.get("message_id", ""),
                "GmailLabels": current.get("labels", ""),
                "MatchedTerms": "; ".join(sorted(terms)),
                "AttachmentFilenames": "; ".join(sorted(attachments)),
                "SourceFile": str(MBOX),
                "Snippet": next(iter(body_snippets.values()), ""),
            })
        if relevant:
            row = {
                "TimestampUTC": format_dt(current.get("date")),
                "InAprilWindow": "Yes" if is_window else "No",
                "Subject": current.get("subject", ""),
                "From": current.get("from", ""),
                "To": current.get("to", ""),
                "MessageID": current.get("message_id", ""),
                "GmailLabels": current.get("labels", ""),
                "MatchedTerms": "; ".join(sorted(terms)),
                "AttachmentFilenames": "; ".join(sorted(attachments)),
                "SourceFile": str(MBOX),
                "Snippet": next(iter(body_snippets.values()), ""),
            }
            keyword_hits.append(row)
            if len(important_examples) < 120:
                important_examples.append(row)
        for filename in sorted(attachments):
            if find_terms(filename) or is_window:
                attachment_hits.append({
                    "TimestampUTC": format_dt(current.get("date")),
                    "InAprilWindow": "Yes" if is_window else "No",
                    "Subject": current.get("subject", ""),
                    "From": current.get("from", ""),
                    "To": current.get("to", ""),
                    "AttachmentFilename": filename,
                    "MatchedTerms": "; ".join(find_terms(filename)),
                    "SourceFile": str(MBOX),
                })

    with MBOX.open("rb") as f:
        for raw_line in f:
            if raw_line.startswith(b"From "):
                finish_message()
                message_count += 1
                current_header = bytearray()
                header_done = False
                current = None
                body_hit_terms = set()
                body_snippets = {}
                attachments = set()
                continue
            if not header_done:
                if raw_line in (b"\n", b"\r\n"):
                    current = parse_headers(bytes(current_header))
                    header_done = True
                    header_terms = find_terms(current.get("headers_text", "") + " " + current.get("subject", ""))
                    for term in header_terms:
                        body_hit_terms.add(term)
                        body_snippets.setdefault(term, short_snippet(current.get("headers_text", ""), term))
                    for match in ATTACH_RE.finditer(current.get("headers_text", "")):
                        attachments.add(match.group(1).strip())
                else:
                    if len(current_header) < 256_000:
                        current_header.extend(raw_line)
                continue
            # Body scanning. Decode only current line to avoid holding messages in memory.
            line = raw_line.decode("utf-8", errors="ignore")
            if "filename" in line.lower():
                for match in ATTACH_RE.finditer(line):
                    attachments.add(match.group(1).strip())
            for term, pat in TERM_PATTERNS:
                if term not in body_hit_terms and pat.search(line):
                    body_hit_terms.add(term)
                    body_snippets[term] = short_snippet(line, term) or line.strip()[:500]
        finish_message()

    headers = ["TimestampUTC", "InAprilWindow", "Subject", "From", "To", "MessageID", "GmailLabels", "MatchedTerms", "AttachmentFilenames", "SourceFile", "Snippet"]
    write_csv(OUT / "MBOX_Relevant_Hits.csv", keyword_hits, headers)
    write_csv(OUT / "MBOX_April19_26_Messages.csv", window_hits, ["TimestampUTC", "Subject", "From", "To", "MessageID", "GmailLabels", "MatchedTerms", "AttachmentFilenames", "SourceFile", "Snippet"])
    write_csv(OUT / "MBOX_Attachment_Hits.csv", attachment_hits, ["TimestampUTC", "InAprilWindow", "Subject", "From", "To", "AttachmentFilename", "MatchedTerms", "SourceFile"])

    report = []
    report.append("# MBOX Evidence Audit\n\n")
    report.append(f"Source file: `{MBOX}`\n\n")
    report.append(f"File size: {MBOX.stat().st_size / 1024**3:.2f} GB\n\n")
    report.append(f"Messages scanned: {message_count}\n\n")
    report.append(f"Messages dated April 19-26, 2024 UTC: {window_count}\n\n")
    report.append(f"Relevant keyword/header/body hits retained: {len(keyword_hits)}\n\n")
    report.append(f"Attachment filename hits retained: {len(attachment_hits)}\n\n")
    report.append("## Interpretation\n\n")
    if window_count or keyword_hits:
        report.append("The MBOX contains potentially relevant email evidence or April-window message records. It should not be deleted unless you have another preserved copy or can reliably re-download it from Google Takeout.\n\n")
    else:
        report.append("No April-window message records or relevant keyword hits were found by this streaming audit. If space is critical, this file is less important than the curated reports, but deletion should still consider whether it can be re-downloaded.\n\n")
    report.append("## Top Relevant Examples\n\n")
    for row in important_examples[:40]:
        report.append(f"- {row['TimestampUTC']} | Subject: {row['Subject']} | Terms: {row['MatchedTerms']} | Attachments: {row['AttachmentFilenames']} | Source: `{MBOX}`\n")
    report.append("\n## Privacy Note\n\n")
    report.append("This audit intentionally records headers, attachment names, matched terms, and short snippets only, not full private email bodies.\n")
    (OUT / "MBOX_Evidence_Audit.md").write_text("".join(report), encoding="utf-8")

    print(f"Messages scanned: {message_count}")
    print(f"April-window messages: {window_count}")
    print(f"Relevant hits: {len(keyword_hits)}")
    print(f"Attachment hits: {len(attachment_hits)}")
    print(f"Report: {OUT / 'MBOX_Evidence_Audit.md'}")


if __name__ == "__main__":
    analyze()
