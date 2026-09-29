#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build.py - genererar app/index.html från guardens regler och senaste
testkörning. Läser guard.py (tillåtet: läsning), kör test_guard.py --json och
stoppar in resultatet i app/template.html.

    python3 app/build.py                 # använder .claude/hooks/
    GUARD_DIR=.claude/hooks-proposed python3 app/build.py

Ingen extern dependency. Avslutar med kod 1 om testkörningen inte är grön,
men sidan byggs ändå (så att FEL syns på dashboarden).
"""

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD_DIR = os.path.join(ROOT, os.environ.get("GUARD_DIR", ".claude/hooks"))
TEMPLATE = os.path.join(ROOT, "app", "template.html")
OUTPUT = os.path.join(ROOT, "app", "index.html")


def load_guard():
    spec = importlib.util.spec_from_file_location("guard", os.path.join(GUARD_DIR, "guard.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rule_sets(guard):
    sets = getattr(guard, "RULE_SETS", None)
    if sets is None:  # äldre guard utan RULE_SETS
        names = [("Git-historik", "GIT_REWRITE"), ("Produktion och deploy", "PROD_AND_DEPLOY"),
                 ("Kubernetes, k3s och Multipass", "KUBERNETES"), ("Katastrofalt", "CATASTROPHIC"),
                 ("Destruktivt", "DESTRUCTIVE")]
        sets = [(n, getattr(guard, a)) for n, a in names if hasattr(guard, a)]
    return [{"name": name, "rules": [{"level": lvl, "pattern": pat, "reason": why} for lvl, pat, why in rules]}
            for name, rules in sets]


def run_tests():
    proc = subprocess.run([sys.executable, os.path.join(GUARD_DIR, "test_guard.py"), "--json"],
                          capture_output=True, text=True, cwd=GUARD_DIR)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        # äldre test_guard.py utan --json: tolka textutskriften
        cases = []
        for line in proc.stdout.splitlines():
            if line.startswith(("OK ", "FEL")):
                mark, rest = line[:3].strip(), line[5:]
                actual, rest = rest[:5].strip(), rest[5:]
                expected = rest[rest.index("(vänta") + 7:rest.index(")")].strip()
                shown = rest[rest.index(")") + 1:].strip()
                cases.append({"tool": "Bash", "shown": shown, "expected": expected,
                              "actual": actual, "reason": "", "ok": mark == "OK"})
        return {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "total": len(cases), "ok": sum(c["ok"] for c in cases), "legacy": 32, "cases": cases}


def main():
    guard = load_guard()
    tests = run_tests()
    data = {
        "built": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "guard_dir": os.path.relpath(GUARD_DIR, ROOT),
        "rule_sets": rule_sets(guard),
        "notes": [{"level": lvl, "text": txt} for lvl, txt in getattr(guard, "POLICY_NOTES", [])],
        "sensitive": list(getattr(guard, "SENSITIVE", [])),
        "tests": tests,
    }
    html = open(TEMPLATE, encoding="utf-8").read()
    # </script> i JSON skulle bryta sidan; escapa snedstrecket
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = html.replace("__DATA_JSON__", payload)
    with open(OUTPUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    print("skrev {} ({} testfall, {} OK, {} regelgrupper)".format(
        os.path.relpath(OUTPUT, ROOT), tests["total"], tests["ok"], len(data["rule_sets"])))
    sys.exit(0 if tests["ok"] == tests["total"] else 1)


if __name__ == "__main__":
    main()
