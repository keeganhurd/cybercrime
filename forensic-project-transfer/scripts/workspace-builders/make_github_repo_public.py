import json
import subprocess
import sys
import urllib.request
import urllib.error


OWNER = "keeganhurd"
REPO = "cybercrime"


def get_github_token():
    query = "protocol=https\nhost=github.com\n\n"
    proc = subprocess.run(
        ["git", "credential", "fill"],
        input=query,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git credential fill failed")
    values = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    token = values.get("password")
    if not token:
        raise RuntimeError("Git Credential Manager did not return a GitHub token/password.")
    return token


def github_request(method, path, token, payload=None):
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codex-local-evidence-publisher",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API HTTP {exc.code}: {body}") from exc


def main():
    token = get_github_token()
    status, before = github_request("GET", f"/repos/{OWNER}/{REPO}", token)
    print(f"Before visibility: {before.get('visibility')} private={before.get('private')}")
    status, after = github_request("PATCH", f"/repos/{OWNER}/{REPO}", token, {"private": False})
    print(f"After visibility: {after.get('visibility')} private={after.get('private')}")
    print(f"HTML URL: https://{OWNER}.github.io/{REPO}/")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
