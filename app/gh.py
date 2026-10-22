"""All GitHub access goes through here (gh CLI today; swap for a GitHub App token later)."""
import json
import os
import shutil
import subprocess


class GhError(RuntimeError):
    pass


def _run(args, timeout=60):
    p = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise GhError((p.stderr or p.stdout).strip()[:300])
    return p.stdout


def api(path, raw=False):
    args = ["api", path]
    if raw:
        args += ["-H", "Accept: application/vnd.github.raw+json"]
    out = _run(args)
    return out if raw else json.loads(out or "null")


def list_repos(org):
    out = _run(["repo", "list", org, "--limit", "1000", "--json",
                "name,defaultBranchRef,isArchived,isEmpty,primaryLanguage,pushedAt,visibility"])
    return json.loads(out)


def branches(org, repo):
    out = _run(["api", "--paginate", f"repos/{org}/{repo}/branches?per_page=100", "--jq", ".[].name"])
    return [b for b in out.splitlines() if b]


def head_sha(org, repo, branch):
    return api(f"repos/{org}/{repo}/commits/{branch}")["sha"]


def tree(org, repo, ref):
    return api(f"repos/{org}/{repo}/git/trees/{ref}?recursive=1")


def file_text(org, repo, path, ref):
    return api(f"repos/{org}/{repo}/contents/{path}?ref={ref}", raw=True)


def languages(org, repo):
    return api(f"repos/{org}/{repo}/languages") or {}


def git_env():
    """Use gh as the only git credential helper: other helpers (e.g. osxkeychain) can block forever
    waiting for a dialog when this runs in the background. Nothing secret goes on the command line."""
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": "",
            "GIT_CONFIG_KEY_1": "credential.helper", "GIT_CONFIG_VALUE_1": "!gh auth git-credential"}


def run(args, timeout=120):
    """gh command, raw stdout."""
    return _run(args, timeout=timeout)


def clone_or_update(org, repo, branch, dest):
    """Shallow clone of one branch, cached on disk; used only for usage search before AI calls."""
    if (dest / ".git").exists():
        env = git_env()
        try:
            for cmd in (["fetch", "--depth", "1", "origin", branch], ["reset", "--hard", "FETCH_HEAD"]):
                subprocess.run(["git", "-C", str(dest), *cmd], capture_output=True, timeout=90, check=True, env=env)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            shutil.rmtree(dest)  # broken cache: start fresh
    if dest.exists():
        shutil.rmtree(dest)  # leftover from an interrupted clone
    dest.parent.mkdir(parents=True, exist_ok=True)
    _run(["repo", "clone", f"{org}/{repo}", str(dest), "--",
          "--depth", "1", "--branch", branch, "--single-branch"], timeout=600)
