import json
import subprocess
import urllib.request
import urllib.error


OWNER = "keeganhurd"
REPO = "cybercrime"


def get_token():
    proc = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        text=True,
        capture_output=True,
        check=False,
    )
    values = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values["password"]


token = get_token()
req = urllib.request.Request(
    f"https://api.github.com/repos/{OWNER}/{REPO}/pages",
    headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "codex-local-pages-checker",
    },
)
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        print(json.dumps({
            "status": data.get("status"),
            "html_url": data.get("html_url"),
            "source": data.get("source"),
            "protected_domain_state": data.get("protected_domain_state"),
            "cname": data.get("cname"),
        }, indent=2))
except urllib.error.HTTPError as exc:
    print(exc.code)
    print(exc.read().decode("utf-8", errors="replace"))
