#!/usr/bin/env python3
# Coleta estatisticas de vulnerabilidade e grava JSON para o Zabbix
# Script identico em qualquer host Linux. Diferencas por host ficam em
# /etc/zabbix-vuln/extra-skip-dirs (uma linha por diretorio a ignorar).
import json, os, shutil, subprocess, tempfile, time
from collections import Counter, defaultdict
from datetime import datetime

OUT_DIR = "/var/lib/zabbix-vuln"
OUT_FILE = os.path.join(OUT_DIR, "report.json")
CACHE_DIR = "/var/cache/trivy"
EXTRA_SKIP_FILE = "/etc/zabbix-vuln/extra-skip-dirs"
SKIP_DIRS = ["/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp",
             "/var/lib/docker", "/var/lib/containers", "/mnt", "/media"]
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEV_ORDER = {s: i for i, s in enumerate(reversed(SEVS))}
TOP_N = 15
RPM_KERNEL = {"kernel", "kernel-core", "kernel-modules", "kernel-modules-core",
              "kernel-modules-extra", "kernel-devel", "kernel-devel-matched", "kernel-uki-virt"}
DEB_KERNEL_PREFIXES = ("linux-image-", "linux-modules-", "linux-headers-",
                        "linux-tools-", "linux-cloud-tools-", "linux-buildinfo-",
                        "pve-kernel-", "proxmox-kernel-")
RUNNING = os.uname()[2]
RUNNING_NOARCH = RUNNING.rsplit(".", 1)[0]

def load_skip_dirs():
    dirs = list(SKIP_DIRS)
    if os.path.isfile(EXTRA_SKIP_FILE):
        with open(EXTRA_SKIP_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    dirs.append(line)
    return dirs

def run(cmd, timeout=3600):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def sev_dict(c):
    return {s: c.get(s, 0) for s in SEVS}

def stale_kernel(pkg, ver):
    v = (ver or "").split(":")[-1]
    if pkg in RPM_KERNEL or pkg.startswith(("kernel-debug", "kernel-rt")):
        return v != RUNNING_NOARCH
    if pkg.startswith(DEB_KERNEL_PREFIXES) and any(ch.isdigit() for ch in pkg):
        return RUNNING not in pkg
    return False

def collect_rpm():
    pm = shutil.which("dnf") or shutil.which("yum")
    tool = os.path.basename(pm)
    adv, pkgs = {}, set()
    rc, out, err = run([pm, "-q", "updateinfo", "list", "--security"], 900)
    if rc != 0:
        return {"status": "error", "error": err.strip()[-300:]}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 3 and "/Sec" in p[1]:
            adv[p[0]] = p[1].split("/")[0]
            pkgs.add(p[2])
    cve_cmd = [pm, "-q", "updateinfo", "list", "--security", "--with-cve"] if tool == "dnf" \
        else [pm, "-q", "updateinfo", "list", "cves"]
    rc, out, err = run(cve_cmd, 900)
    cves = {l.split()[0] for l in out.splitlines() if l.startswith("CVE-")}
    advc = Counter(adv.values())
    reboot = -1
    if shutil.which("needs-restarting"):
        reboot = 1 if run(["needs-restarting", "-r"], 300)[0] == 1 else 0
    rc, out, err = run(["rpm", "-qa", "--qf", "%{INSTALLTIME}\n"], 300)
    last = max(int(x) for x in out.split() if x.isdigit())
    return {"status": "ok", "tool": tool,
            "advisories": {k: advc.get(k, 0) for k in ["Critical", "Important", "Moderate", "Low"]},
            "advisories_total": len(adv), "cves_pending": len(cves),
            "packages_pending": len(pkgs), "reboot_required": reboot,
            "last_patch_days": int((time.time() - last) / 86400)}

def collect_deb():
    rc, out, err = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], 600)
    if rc != 0:
        return {"status": "error", "error": err.strip()[-300:]}
    sec = {l.split()[1] for l in out.splitlines() if l.startswith("Inst ") and "-security" in l}
    return {"status": "ok", "tool": "apt", "packages_pending": len(sec),
            "reboot_required": 1 if os.path.exists("/var/run/reboot-required") else 0,
            "last_patch_days": int((time.time() - os.path.getmtime("/var/lib/dpkg/status")) / 86400)}

def cvss(v):
    src = v.get("CVSS") or {}
    for k in ("nvd", "redhat", "ghsa"):
        s = (src.get(k) or {}).get("V3Score")
        if s:
            return float(s)
    sc = [float(x.get("V3Score") or 0) for x in src.values() if isinstance(x, dict)]
    return max(sc) if sc else 0.0

def collect_trivy():
    tv = shutil.which("trivy")
    if not tv:
        return {"status": "not_installed"}
    cmd = [tv, "rootfs", "--scanners", "vuln", "--format", "json", "--quiet",
           "--cache-dir", CACHE_DIR, "--timeout", "45m"]
    for d in load_skip_dirs():
        cmd += ["--skip-dirs", d]
    cmd.append("/")
    rc, out, err = run(cmd, 3600)
    if rc != 0:
        return {"status": "error", "error": err.strip()[-300:]}
    data = json.loads(out)
    cves, by_class, pkg_rank = {}, Counter(), defaultdict(Counter)
    stale = 0
    for r in data.get("Results") or []:
        cls = r.get("Class", "unknown")
        for v in r.get("Vulnerabilities") or []:
            vid, sev, pkg = v.get("VulnerabilityID"), v.get("Severity", "UNKNOWN"), v.get("PkgName", "?")
            if cls == "os-pkgs" and stale_kernel(pkg, v.get("InstalledVersion")):
                stale += 1
                continue
            by_class[cls] += 1
            pkg_rank[pkg][sev] += 1
            c = cves.setdefault(vid, {"sev": sev, "score": 0.0, "fix": False, "pub": None,
                                      "pkgs": set(), "cls": set()})
            if SEV_ORDER.get(sev, 0) > SEV_ORDER.get(c["sev"], 0):
                c["sev"] = sev
            c["score"] = max(c["score"], cvss(v))
            c["fix"] = c["fix"] or bool(v.get("FixedVersion"))
            c["pkgs"].add(pkg)
            c["cls"].add(cls)
            pub = v.get("PublishedDate")
            if pub and (c["pub"] is None or pub < c["pub"]):
                c["pub"] = pub
    now = datetime.utcnow()
    ages = [(now - datetime.strptime(c["pub"][:10], "%Y-%m-%d")).days
            for c in cves.values() if c["fix"] and c["sev"] in ("CRITICAL", "HIGH") and c["pub"]]
    fix_cls = {k: sev_dict(Counter(c["sev"] for c in cves.values() if c["fix"] and k in c["cls"]))
               for k in ("os-pkgs", "lang-pkgs")}
    tp = sorted(pkg_rank.items(), key=lambda kv: (kv[1]["CRITICAL"], kv[1]["HIGH"], sum(kv[1].values())), reverse=True)[:TOP_N]
    tc = sorted(cves.items(), key=lambda kv: (SEV_ORDER.get(kv[1]["sev"], 0), kv[1]["score"]), reverse=True)[:TOP_N]
    return {"status": "ok", "running_kernel": RUNNING,
            "stale_kernel_findings": stale,
            "unique_cves": sev_dict(Counter(c["sev"] for c in cves.values())),
            "fixable": sev_dict(Counter(c["sev"] for c in cves.values() if c["fix"])),
            "fixable_by_class": fix_cls,
            "unique_total": len(cves),
            "findings_by_class": dict(by_class),
            "oldest_fixable_crit_high_days": max(ages) if ages else 0,
            "top_packages": [{"package": p, "critical": c["CRITICAL"], "high": c["HIGH"],
                              "medium": c["MEDIUM"], "low": c["LOW"], "unknown": c["UNKNOWN"],
                              "total": sum(c.values())} for p, c in tp],
            "top_cves": [{"cve": k, "severity": c["sev"], "score": c["score"], "fixable": c["fix"],
                          "class": ",".join(sorted(c["cls"])),
                          "packages": ",".join(sorted(c["pkgs"]))[:120]} for k, c in tc]}

def main():
    t0 = time.time()
    rep = {"timestamp": int(t0), "hostname": os.uname()[1]}
    try:
        if shutil.which("dnf") or shutil.which("yum"):
            rep["pkgmgr"] = collect_rpm()
        elif shutil.which("apt-get"):
            rep["pkgmgr"] = collect_deb()
    except Exception as e:
        rep["pkgmgr"] = {"status": "error", "error": str(e)[:300]}
    try:
        rep["trivy"] = collect_trivy()
    except Exception as e:
        rep["trivy"] = {"status": "error", "error": str(e)[:300]}
    rep["duration"] = int(time.time() - t0)
    rep["status"] = "error" if any(rep.get(k, {}).get("status") == "error" for k in ("pkgmgr", "trivy")) else "ok"
    os.makedirs(OUT_DIR, exist_ok=True)
    os.chmod(OUT_DIR, 0o755)
    fd, tmp = tempfile.mkstemp(dir=OUT_DIR)
    with os.fdopen(fd, "w") as f:
        json.dump(rep, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT_FILE)

if __name__ == "__main__":
    main()
