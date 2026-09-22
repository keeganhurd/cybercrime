import csv
import subprocess
from pathlib import Path
from datetime import datetime


MBOX = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\All mail Including Spam and Trash-002.mbox")
OUT = Path(r"C:\Users\thoma\Documents\Cyber Crimes Tools\Takeout Extracted\_forensic_outputs")

TERMS = [
    "FILE_5531.pdf",
    "HELO Payment Services LLC EIN.pdf",
    "HELO Payment Services",
    "CP 575",
    "147C",
    "EIN",
    "Navy Federal",
    "Virtue Capital",
    "DocuSign",
    "LCF Group",
    "bank statement",
    "Jonathan Braese",
    "Venmo",
    "drive.google.com",
    "docs.google.com",
    "keeganhurd@gmail.com",
]

DATE_PATTERNS = [
    r"^Date: .*(19|20|21|22|23|24|25|26) Apr 2024",
    r"^Date: .*Apr (19|20|21|22|23|24|25|26), 2024",
]


def run_rg(args, timeout=900):
    cmd = ["rg", "--no-messages"] + args + [str(MBOX)]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    if not MBOX.exists():
        raise SystemExit(f"Missing MBOX: {MBOX}")

    counts = []
    context_rows = []
    for term in TERMS:
        code, stdout, stderr = run_rg(["-i", "-F", "--count-matches", term], timeout=900)
        count = 0
        if stdout.strip():
            # Format is path:count for ripgrep with an explicit file.
            try:
                count = int(stdout.strip().split(":")[-1])
            except Exception:
                count = 0
        counts.append({"Term": term, "MatchCount": count, "SourceFile": str(MBOX)})
        if count:
            code, ctx, _ = run_rg(["-i", "-F", "-n", "-C", "2", "-m", "25", term], timeout=900)
            (OUT / f"MBOX_context_{safe(term)}.txt").write_text(ctx, encoding="utf-8", errors="replace")
            for line in ctx.splitlines()[:160]:
                if line.strip():
                    context_rows.append({"Term": term, "ContextLine": line[:1200], "SourceFile": str(MBOX)})

    date_rows = []
    for pattern in DATE_PATTERNS:
        code, stdout, stderr = run_rg(["-P", "-n", "-m", "500", pattern], timeout=900)
        for line in stdout.splitlines():
            date_rows.append({"Pattern": pattern, "Line": line[:1200], "SourceFile": str(MBOX)})

    with (OUT / "MBOX_Quick_Term_Counts.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Term", "MatchCount", "SourceFile"])
        w.writeheader()
        w.writerows(counts)
    with (OUT / "MBOX_Quick_Context_Hits.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Term", "ContextLine", "SourceFile"])
        w.writeheader()
        w.writerows(context_rows)
    with (OUT / "MBOX_Quick_April_Date_Header_Hits.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Pattern", "Line", "SourceFile"])
        w.writeheader()
        w.writerows(date_rows)

    total_high_value = sum(c["MatchCount"] for c in counts if c["Term"] not in {"EIN", "Venmo", "keeganhurd@gmail.com"})
    report = []
    report.append("# Quick MBOX Evidence Audit\n\n")
    report.append(f"Source file: `{MBOX}`\n\n")
    report.append(f"File size: {MBOX.stat().st_size / 1024**3:.2f} GB\n\n")
    report.append("## Term Counts\n\n")
    for row in counts:
        report.append(f"- {row['Term']}: {row['MatchCount']}\n")
    report.append(f"\nApril 19-26, 2024 Date header sample hits captured: {len(date_rows)}\n\n")
    report.append("## Assessment\n\n")
    if total_high_value:
        report.append("This MBOX contains high-value terms tied to the case theory. It should be preserved or at least be clearly re-downloadable from Google Takeout before deletion.\n\n")
    else:
        report.append("This quick audit did not find high-value terms beyond broad/common terms. If storage is critical and the file can be re-downloaded, it is a candidate for deletion after documenting its path and source.\n\n")
    report.append("## Source Tracking\n\n")
    report.append("This is not a ZIP part. The source artifact is the standalone MBOX file itself. If deleted locally, record the Google Takeout export/account/date so it can be downloaded again if POPD or SA asks for the raw source.\n\n")
    report.append("## Privacy Note\n\n")
    report.append("Context files contain short rg context lines only, not full email bodies.\n")
    (OUT / "MBOX_Quick_Evidence_Audit.md").write_text("".join(report), encoding="utf-8")

    print("Quick MBOX audit complete")
    print(f"Source: {MBOX}")
    print(f"Date header sample hits: {len(date_rows)}")
    for row in counts:
        print(f"{row['Term']}: {row['MatchCount']}")
    print(f"Report: {OUT / 'MBOX_Quick_Evidence_Audit.md'}")


def safe(term):
    return "".join(ch if ch.isalnum() else "_" for ch in term)[:60]


if __name__ == "__main__":
    main()
