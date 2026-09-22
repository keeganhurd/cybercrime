import json
import subprocess
import sys
import urllib.request
import urllib.error


OWNER = "keeganhurd"
REPO = "cybercrime"


def get_github_token():
    proc = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
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


def request(method, path, token, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "codex-local-pages-enabler",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, {"error": body}


def main():
    token = get_github_token()
    payload = {"source": {"branch": "gh-pages", "path": "/"}}
    status, result = request("POST", f"/repos/{OWNER}/{REPO}/pages", token, payload)
    if status in (201, 202):
        print(f"Pages enabled: {result.get('html_url') or f'https://{OWNER}.github.io/{REPO}/'}")
        return
    if status == 409 or status == 422:
        status, result = request("PUT", f"/repos/{OWNER}/{REPO}/pages", token, payload)
        if status in (200, 201, 202, 204):
            print(f"Pages updated: https://{OWNER}.github.io/{REPO}/")
            return
    print(f"Pages API status: {status}")
    print(json.dumps(result, indent=2)[:2000])
    if status >= 400:
        sys.exit(1)


if __name__ == "__main__":
    main()
