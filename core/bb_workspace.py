"""bb_workspace.py - expose the bug bounty workspace through the WebForge API.

Brings the old standalone Flask dashboard (`bugbounty/webui`) into WebForge:
runs `scripts/bb.py` actions against recon targets in the background with
live streaming output, plus read-only views over recon/scans/cve/loot and
markdown report generation.

The bugbounty workspace lives at `WEBFORGE_BB_WORKSPACE` (default
`/root/hakinet/bugbounty`) and is managed by `scripts/bb.py`.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from webforg.core.config import get_settings

# Centralized path (env-overridable via WEBFORGE_BB_WORKSPACE); the default
# `/root/hakinet/bugbounty` is preserved.
WORKSPACE = get_settings().bugbounty_dir
SCRIPTS = WORKSPACE / "scripts"

_spec = importlib.util.spec_from_file_location("bb_workspace_helpers", SCRIPTS / "bb.py")
bb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bb)

BB = [sys.executable, "-u", str(SCRIPTS / "bb.py")]
RECON = bb.RECON
SCANS = bb.SCANS
LOOT = bb.LOOT
CVE = bb.CVE
WORDLISTS = WORKSPACE / "wordlists"

ACTIONS = {
    "recon":    (["recon"], "Recon (subs -> dns -> ports -> httpx -> urls)"),
    "urls":     (["urls"], "URL harvest (gau + waybackurls)"),
    "scan":     (["scan"], "Nuclei vulnerability scan"),
    "vuln":     (["vuln"], "Deep vulnerability scan (wapiti: SQLi/XSS/XXE/SSRF/cmd injection)"),
    "crawl":    (["crawl"], "Crawl site, extract endpoints & JS secrets"),
    "xss":      (["xss"], "XSS scan (dalfox)"),
    "crlf":     (["crlf"], "CRLF injection"),
    "takeover": (["takeover"], "Subdomain takeover"),
    "redirect": (["redirect"], "Open redirect"),
    "cors":     (["cors"], "CORS misconfig"),
    "ssrf":     (["ssrf"], "SSRF check"),
    "git":      (["git"], "Exposed .git dump"),
    "tls":      (["tls"], "TLS analysis (testssl.sh)"),
    "cert":     (["cert"], "crt.sh cert transparency subdomains"),
    "param":    (["param"], "Parameter discovery"),
    "jwt":      (["jwt"], "JWT analysis"),
}

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# ----------------------------------------------------------------------
# Background job runner (threaded, one job at a time)
# ----------------------------------------------------------------------


class Job:
    def __init__(self, cmd, label, target):
        self.cmd = cmd
        self.label = label
        self.target = target
        self.buf = []
        self.done = False
        self.code = None
        self.stopped = False
        self.proc = None
        self.start = time.time()
        self.end = None
        self.lock = threading.Lock()

    def append(self, line):
        with self.lock:
            self.buf.append(line)

    def tail(self, n=200):
        with self.lock:
            return self.buf[-n:]

    def stop(self):
        """Request termination of the running process (SIGTERM, then SIGKILL)."""
        with self.lock:
            if self.stopped:
                return
            self.stopped = True
        proc = self.proc
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            if proc.pid and hasattr(os, "killpg"):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        t = threading.Thread(target=self._escalate, args=(proc,), daemon=True)
        t.start()

    def _escalate(self, proc):
        time.sleep(2)
        try:
            if proc.poll() is None:
                proc.kill()
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass


JOBS = []
ACTIVE = None
LOCK = threading.Lock()
JOB_ID = 0


def _run_job(job):
    """Execute the command, streaming output into job.buf."""
    global ACTIVE
    try:
        proc = subprocess.Popen(
            job.cmd, env=bb.env_path(), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True,
        )
        job.proc = proc
        for line in proc.stdout:
            if job.stopped:
                break
            job.append(line.rstrip("\n"))
        try:
            job.code = proc.wait()
        except Exception:
            job.code = -9 if job.stopped else 1
    except Exception as e:
        job.append(f"[!] {e}")
        job.code = 1
    finally:
        job.done = True
        job.end = time.time()
        with LOCK:
            JOBS.append(job)


def start_job(cmd, label, target):
    """Start a job in a background thread. Returns the Job (or None if busy)."""
    global ACTIVE, JOB_ID
    with LOCK:
        if ACTIVE and not ACTIVE.done:
            return None
        JOB_ID += 1
        job = Job(cmd, label, target)
        job.id = JOB_ID
        ACTIVE = job
    t = threading.Thread(target=_run_job, args=(job,), daemon=True)
    t.start()
    return job


def active_job():
    return ACTIVE if ACTIVE and not ACTIVE.done else None


def stop_active():
    global ACTIVE
    with LOCK:
        job = ACTIVE if ACTIVE and not ACTIVE.done else None
        if job is None:
            return None
    job.append("[*] job stopped by user")
    job.stop()
    return job


def shell_split(s):
    return shlex.split(s, posix=True)


def normalize_target(raw):
    """Reduce a URL/domain input to a folder-safe target name."""
    name = re.sub(r"^[a-z]+://", "", raw.strip(), flags=re.I).rstrip("/").split("/")[0]
    name = re.sub(r"[:\s]+", "-", name)
    name = (name or "unknown").lower()
    # Reject path-traversal components — even after sanitization "." and ".."
    # are never valid target hostnames.
    if name in (".", "..", ""):
        raise HTTPException(status_code=400, detail="invalid target name")
    return name


def _safe_target_dir(name):
    """Resolve recon/<name> ensuring the result stays inside RECON."""
    base = RECON.resolve()
    td = (base / name).resolve()
    if base not in td.parents and td != base:
        raise HTTPException(status_code=400, detail="invalid target name")
    return td


def save_target(raw):
    """Register a target: create recon/<name>/ and record the input in sources.txt."""
    name = normalize_target(raw)
    td = _safe_target_dir(name)
    td.mkdir(parents=True, exist_ok=True)
    src = td / "sources.txt"
    entries = {l for l in src.read_text().splitlines() if l.strip()} if src.exists() else set()
    entries.add(raw.strip())
    src.write_text("\n".join(sorted(entries)) + "\n")
    return name


def _read_entries(path):
    if not path.exists():
        return []
    return [l for l in path.read_text(errors="ignore").splitlines() if l.strip()]


def _target_in_file(target, path):
    """Heuristic: does this scan file mention the target (hostnames/URLs)?"""
    try:
        head = path.read_text(errors="ignore")[:20000]
    except Exception:
        return False
    name = target.lower().split(":")[0].split("/")[0]
    return name and name in head.lower()


def _parse_severity(line):
    l = line.lower()
    m = re.search(r"\[(critical|high|medium|low|info)\]", l)
    if m:
        return m.group(1)
    if "cve-" in l or "vulnerable" in l:
        return "high"
    if "offered (ok)" in l or "not offered" in l:
        return "info"
    if "null cipher" in l:
        return "critical"
    if "deprecated" in l:
        return "low"
    if ("triple des" in l or "obsoleted cbc" in l or "export cipher" in l
            or "low: 64 bit" in l or "anonymous null" in l):
        return "medium"
    return "info"


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TLS_KEEP = re.compile(
    r"(not offered|offered|advertised|vulnerable|CVE-\d+|heartbleed|poodle|breach|drown|"
    r"robot|logjam|sweet32|beast|crime|renegotiation|session resumption|hostname mismatch|"
    r"common name|issuer|ocsp|dh param|server cipher order|forward secrecy|deprecated)",
    re.I)
_TLS_SKIP = re.compile(
    r"(fatal error|oops:|unable to open a socket|consider increasing|line \d+:|"
    r"tcp connect problem|connect:|connection timed out|network is unreachable)", re.I)
_TLS_HEADER = re.compile(r"^\s*(testing\b|hexcode\b|done\b)", re.I)


def _tls_entries(path):
    """Extract meaningful status lines from a testssl.sh text report (strip ANSI, drop noise)."""
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(errors="ignore").splitlines():
        line = _ANSI_RE.sub("", raw).strip()
        if not line or _TLS_HEADER.match(line) or _TLS_SKIP.search(line):
            continue
        if _TLS_KEEP.search(line):
            out.append(line)
    return out


def _gather_findings(target):
    """Collect findings from scans/ for a target (autoscan + exploit + cve + wapiti)."""
    findings = {}
    for sub in ("autoscan", "cve", "exploit", "xss", "crlf", "sql", "screenshots", "tls", "ffuf",
                "nuclei", "cors", "git", "redirect", "ssrf", "takeover"):
        d = SCANS / sub
        if not d.exists():
            continue
        for f in sorted(d.glob("*.txt")):
            if target not in f.name and not _target_in_file(target, f):
                continue
            entries = _tls_entries(f) if sub == "tls" else _read_entries(f)
            if entries:
                findings.setdefault(sub, []).extend(entries)
    vd = SCANS / "vuln"
    if vd.exists():
        for f in sorted(vd.glob("*.json")):
            try:
                data = json.loads(f.read_text(errors="ignore"))
            except Exception:
                continue
            tgt = (data.get("infos") or {}).get("target", "")
            if tgt and target.lower().split(":")[0].split("/")[0] not in tgt.lower():
                continue
            if not tgt and not _target_in_file(target, f):
                continue
            vuls = data.get("vulnerabilities") or {}
            entries = []
            for vtype, hits in vuls.items():
                for h in hits:
                    path = h.get("path", "") or h.get("url", "")
                    info = h.get("info") or ""
                    if info:
                        try:
                            parsed = json.loads(info)
                            info = parsed.get("name", info)
                        except Exception:
                            pass
                    entries.append(f"[{vtype}] {path} {info}".strip())
            if entries:
                findings.setdefault("vuln", []).extend(entries)
    return findings


def generate_report(target, include_all=False):
    """Build a markdown report for a target. Returns (markdown, findings_count)."""
    td = _safe_target_dir(target)
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    L = [f"# Bug bounty report: {target}", "", f"_generated {now} — bug bounty workspace_", ""]

    L += ["## 1. Assets", ""]
    if td.exists():
        for p in sorted(td.glob("*.txt")):
            n = sum(1 for _ in p.open(errors="ignore")) if p.stat().st_size else 0
            if n or include_all:
                L.append(f"- **{p.name}**: {n} entries")
    else:
        L.append("_no recon data for this target yet_")
    L.append("")

    findings = _gather_findings(target)
    total = sum(len(v) for v in findings.values())
    if findings:
        L += ["## 2. Findings", ""]
        for label in sorted(findings):
            for entry in findings[label]:
                sev = _parse_severity(entry)
                L.append(f"- **[{sev.upper()}]** `{entry}`  _(source: {label})_")
        L.append("")
    else:
        L += ["## 2. Findings", "", "_no findings collected yet_", ""]

    L += ["## 3. Timeline", "", f"- `{now}` — report generated", "",
          "## 4. Next steps", "",
          "- Verify each finding manually (false positives are common).",
          "- Reproduce before reporting.",
          "- Check program scope and rules of engagement.",
          ""]
    return "\n".join(L), total


# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------

router = APIRouter(prefix="/api/bb", tags=["bugbounty"])


class RunReq(BaseModel):
    action: str
    target: str
    args: str = ""
    hosts: str = ""


class ExploitReq(BaseModel):
    cve: str
    target: str
    severity: str = ""


class ReportReq(BaseModel):
    target: str
    include_all: bool = False


def _job_dict(j):
    dur = (j.end or time.time()) - j.start
    return {
        "id": j.id, "label": j.label, "target": j.target,
        "done": j.done, "stopped": j.stopped, "code": j.code,
        "lines": len(j.buf), "cmd": " ".join(j.cmd),
        "start": datetime.fromtimestamp(j.start).strftime("%H:%M:%S"),
        "duration": round(dur, 1),
    }


@router.get("/status")
def bb_status():
    nt = len([d for d in RECON.iterdir() if d.is_dir()]) if RECON.exists() else 0
    ns = len(list(SCANS.rglob("*"))) if SCANS.exists() else 0
    nc = len(list(CVE.glob("*.yaml"))) if CVE.exists() else 0
    nw = len(list(WORDLISTS.glob("*.txt"))) if WORDLISTS.exists() else 0
    nl = len(list(LOOT.rglob("*"))) if LOOT.exists() else 0
    return {"targets": nt, "scans": ns, "cve": nc, "wordlists": nw, "loot": nl,
            "workspace": str(WORKSPACE), "active": active_job() is not None}


@router.get("/actions")
def bb_actions():
    return {"actions": [{"value": k, "label": v[1], "cmd": " ".join(BB + v[0] + ["<target>"])}
                        for k, v in ACTIONS.items()],
            "severities": SEVERITIES}


@router.get("/targets")
def bb_targets():
    if not RECON.exists():
        return {"targets": []}
    out = []
    for d in sorted(RECON.iterdir()):
        if not d.is_dir():
            continue
        files = [{"name": p.name, "size": p.stat().st_size,
                  "lines": len(p.read_text(errors="ignore").splitlines()) if p.stat().st_size else 0}
                 for p in sorted(d.glob("*.txt"))]
        rep = d / "report.md"
        out.append({"name": d.name, "files": files, "report": rep.exists()})
    return {"targets": out}


@router.get("/target/{name}")
def bb_target_files(name: str):
    td = _safe_target_dir(name)
    if not td.exists():
        raise HTTPException(status_code=404, detail="no such target")
    files = []
    for p in sorted(td.glob("*.txt")):
        files.append({"name": p.name, "size": p.stat().st_size,
                      "lines": p.read_text(errors="ignore").splitlines()})
    return {"target": name, "files": files}


@router.get("/cve/search")
def bb_cve_search(q: str = "", limit: int = 20):
    q = q.strip().upper()
    limit = min(max(int(limit), 1), 100)
    if not q:
        return []
    results = []
    for f in CVE.glob("*.yaml") if CVE.exists() else []:
        name = f.name.upper()
        if q in name:
            txt = f.read_text(errors="ignore")
            s = re.search(r"severity:\s*(\w+)", txt, re.I)
            results.append({"id": f.stem.upper(), "file": f.name,
                            "severity": s.group(1).lower() if s else "unknown"})
            if len(results) >= limit:
                break
    return results


@router.get("/vuln/cves")
def bb_vuln_cves():
    """CVEs found by wapiti scans (from scans/vuln/*.json)."""
    results = []
    vd = SCANS / "vuln"
    if not vd.exists():
        return results
    for f in sorted(vd.glob("*.json")):
        try:
            data = json.loads(f.read_text(errors="ignore"))
        except Exception:
            continue
        tgt = (data.get("infos") or {}).get("target", "")
        seen = {}
        for vtype, entries in (data.get("vulnerabilities") or {}).items():
            for e in entries:
                info = e.get("info") or ""
                if isinstance(info, dict):
                    info = json.dumps(info)
                for m in re.findall(r"CVE-\d{4}-\d+", info.upper()):
                    desc = info.strip()[:160]
                    seen.setdefault(m, {"cve": m, "target": tgt, "file": f.name,
                                        "vtype": vtype, "info": desc})
                    seen[m]["target"] = seen[m]["target"] or tgt
        results.extend(seen.values())
    results.sort(key=lambda r: r["cve"])
    return results


@router.post("/run")
def bb_run(req: RunReq):
    action = req.action
    target = req.target.strip()
    extra = req.args
    if action not in ACTIONS:
        raise HTTPException(status_code=400, detail=f"unknown action '{action}'")
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    if active_job():
        raise HTTPException(status_code=409, detail="a job is already running")

    saved = save_target(target)

    if action in ("xss", "scan", "crlf", "takeover", "redirect", "cors", "ssrf"):
        if req.hosts:
            target = req.hosts
        else:
            hostfile = RECON / target / "httpx.txt"
            if hostfile.exists():
                target = str(hostfile)

    if action == "crawl":
        target = target if "://" in target else f"https://{target}"
    if action == "git":
        target = target if ".git" in target else f"{target.rstrip('/')}/.git/"

    args = shell_split(extra) if extra else []
    cmd = BB + ACTIONS[action][0] + [target] + args
    job = start_job(cmd, ACTIONS[action][1], req.target.strip())
    if job is None:
        raise HTTPException(status_code=409, detail="a job is already running")
    return {"id": job.id, "label": job.label, "saved": saved}


@router.post("/run-exploit")
def bb_run_exploit(req: ExploitReq):
    cve_id = req.cve.strip().upper()
    target = req.target.strip()
    severity = req.severity.strip()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="cve must be a CVE id, e.g. CVE-2023-25157")
    if not target:
        raise HTTPException(status_code=400, detail="target URL is required")
    if active_job():
        raise HTTPException(status_code=409, detail="a job is already running")

    saved = save_target(target)

    cmd = BB + ["cve", "exploit", cve_id, target]
    if severity:
        cmd += ["-s", severity]
    job = start_job(cmd, f"exploit {cve_id}", target)
    if job is None:
        raise HTTPException(status_code=409, detail="a job is already running")
    return {"id": job.id, "label": f"exploit {cve_id}", "saved": saved}


@router.get("/jobs")
def bb_jobs():
    with LOCK:
        items = []
        if ACTIVE and not ACTIVE.done:
            items.append(_job_dict(ACTIVE))
        items.extend(_job_dict(j) for j in JOBS if j is not None)
    return items


@router.get("/job/{jid}/log")
def bb_job_log(jid: int):
    job = None
    with LOCK:
        for j in [ACTIVE] + JOBS:
            if j and j.id == jid:
                job = j
                break
    if job is None:
        raise HTTPException(status_code=404, detail="no such job")
    return {"id": job.id, "done": job.done, "code": job.code, "lines": job.buf}


@router.get("/history")
def bb_history():
    with LOCK:
        items = [{"id": j.id, "label": j.label, "target": j.target, "code": j.code,
                  "lines": len(j.buf), "cmd": " ".join(j.cmd)}
                 for j in reversed(JOBS[-25:])]
    return items


@router.post("/stop")
def bb_stop():
    job = stop_active()
    if job is None:
        raise HTTPException(status_code=404, detail="no job running")
    return {"ok": True, "id": job.id, "label": job.label}


@router.post("/report/generate")
def bb_report_generate(req: ReportReq):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    md, total = generate_report(target, include_all=req.include_all)
    td = _safe_target_dir(target)
    if not td.exists():
        td.mkdir(parents=True, exist_ok=True)
    out = td / "report.md"
    out.write_text(md)
    return {"ok": True, "file": str(out), "findings": total, "markdown": md}


@router.get("/report/view/{target}")
def bb_report_view(target: str):
    td = _safe_target_dir(target)
    out = td / "report.md"
    if not out.exists():
        raise HTTPException(status_code=404, detail="no report yet — generate one first")
    return {"target": target, "markdown": out.read_text(errors="ignore")}
