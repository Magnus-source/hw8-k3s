#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
guard.py - PreToolUse-hook som fungerar som säkerhetsnät för Claude Code.

Claude Code skickar varje tool-call som JSON på stdin INNAN verktyget körs.
Det här skriptet läser den, klassar anropet och skickar tillbaka ett beslut
som JSON på stdout enligt Claude Codes hook-kontrakt:

    {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny" | "ask",
        "permissionDecisionReason": "..."}}

Tre nivåer:
    DENY   - hårt stopp, verktyget körs aldrig
    ASK    - stoppa och fråga Magnus (human-in-the-loop; det är själva poängen
             med t.ex. git-historik som skrivs om)
    ALLOW  - vi skriver ingenting och avslutar med kod 0. Då tar Claude Codes
             vanliga behörighetsflöde över. Vi auto-godkänner alltså aldrig -
             ett tyst "allow" skulle stänga av den ordinarie behörighetsfrågan.

Design:
    - Mekanik och policy hålls isär. Reglerna längst upp är data som är lätta
      att läsa och utöka. Motorn längst ner rör man sällan.
    - Fail-safe: kan vi inte tolka indatan blockerar vi inte normal drift,
      men de regex-baserade reglerna körs alltid mot råsträngen ändå.
    - Självskydd: hooken vägrar låta agenten skriva om sina egna hook-filer
      eller settings.json, så nätet inte kan monteras ner inifrån. Gäller
      både Write/Edit-verktygen och Bash (redirect, tee, cp, sed -i ...).
    - Uppackning: inbäddade kommandon (ssh host "...", multipass exec vm -- ...,
      kubectl exec pod -- sh -c "...", bash -c "...") packas upp och det inre
      kommandot granskas med samma regler. Man kan alltså inte smita förbi
      genom att köra det farliga kommandot "en nivå in".
    - Allt som matchar en regel loggas till audit-log.jsonl (spårbar logg).

Historik:
    homework-06  grundversion (git, prod, katastrofalt, hemligheter, e-post)
    homework-08  Kubernetes/k3s/Multipass-regler, uppackning av inbäddade
                 kommandon, självskydd även i Bash, kubectl apply-policy
    hw08 rev 2   omslag med argument skalas bort korrekt (timeout 30 cmd,
                 script -q /dev/null cmd, nice -n 10 cmd, xargs -n 1 cmd,
                 sudo -u root cmd), kubectl config view --raw och
                 kubectl get secret -o yaml/json = DENY, självskyddet i Bash
                 reagerar bara när redirect-MÅLET (inte 2>/dev/null) eller
                 destinationen för cp/mv/tee är en hook-fil.
                 Relativa sökvägar tolkas mot "cd"/"pushd" tidigare på samma
                 rad (cd .claude/hooks && echo x > guard.py), cp/mv med
                 -t/--target-directory, och .claude/hooks utan snedstreck.

Referens: https://code.claude.com/docs/en/hooks
"""

import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone

DENY, ASK, ALLOW = "deny", "ask", "allow"
_RANK = {ALLOW: 0, ASK: 1, DENY: 2}

HOOK_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_LOG = os.path.join(HOOK_DIR, "audit-log.jsonl")


# ---------------------------------------------------------------------------
# POLICY - detta är den del du justerar för att passa dina projekt
# ---------------------------------------------------------------------------

# Git-kommandon som skriver om historiken. Standard = ASK, så att du alltid är
# med i loopen. De två verkligt oåterkalleliga (filter-branch/-repo) = DENY.
GIT_REWRITE = [
    (ASK,  r"\bpush\b.*(?:--force\b|(?<!lease)-f\b|--force-with-lease\b)", "force-push skriver om historiken på remote"),
    (ASK,  r"\bpush\b.*(?:--delete\b|\s:\S)",         "raderar en remote-gren"),
    (ASK,  r"\breset\b.*--hard\b",                    "reset --hard slänger ändringar oåterkalleligt"),
    (ASK,  r"\brebase\b",                             "rebase skriver om commit-historiken"),
    (ASK,  r"\bcommit\b.*--amend\b",                  "amend skriver om senaste commit"),
    (ASK,  r"\breflog\b.*(?:expire|delete)\b",        "reflog expire/delete tar bort gits eget skyddsnät"),
    (ASK,  r"\bbranch\b.*\s-D\b",                      "branch -D tvångsraderar en gren"),
    (ASK,  r"\bupdate-ref\b.*\s-d\b",                  "update-ref -d manipulerar refs direkt"),
    (ASK,  r"\bgc\b.*--prune\b",                       "gc --prune kan städa bort oåtkomliga objekt permanent"),
    (ASK,  r"\bclean\b\s+-[A-Za-z]*f",                 "git clean -f raderar ospårade filer"),
    (DENY, r"\bfilter-branch\b|\bfilter-repo\b",       "filter-branch/-repo skriver om HELA historiken"),
]

# Produktion och driftpåverkan. SSH/SCP mot prod = hårt stopp. Deploy och
# tjänststyrning = ASK. Sätt dina egna prod-mönster i PROD_HOSTS.
# (kubectl hanteras numera i KUBERNETES nedan.)
PROD_HOSTS = r"(prod|production|live|\.aws\.|azure|gcp)"
PROD_AND_DEPLOY = [
    (DENY, r"\bssh\b\s+\S*" + PROD_HOSTS,             "SSH mot en produktionsserver är blockerat"),
    (DENY, r"\bscp\b\s+\S*" + PROD_HOSTS,             "SCP mot produktion är blockerat"),
    (ASK,  r"\bdocker(?:\s+compose)?\b.*\bdown\b",     "docker compose down stänger tjänster"),
    (ASK,  r"\bdocker\b.*\brm[i]?\b.*\s-f",            "docker rm/rmi -f tar bort containers/images"),
    (ASK,  r"\bsystemctl\b.*\b(stop|disable|mask)\b",  "systemctl stop/disable stänger en tjänst"),
    (ASK,  r"\bterraform\b.*\b(apply|destroy)\b",      "terraform apply/destroy ändrar infrastruktur"),
    (ASK,  r"\b(vercel|netlify|flyctl|railway)\b.*\b(deploy|--prod|up)\b", "deploy till hosting-plattform"),
    (ASK,  r"\bnpm\b\s+publish\b|\btwine\b\s+upload\b|\bgh\b\s+release\b", "publicering av paket/release"),
]

# Kubernetes / k3s / Multipass (homework-08). Klustret är ett labb, men
# kube-system, noder och namespaces är "infrastruktur" = hårt stopp.
# Vanliga delete/drain/cordon/scale-till-0/rollout restart = ASK.
_NS_KUBE_SYSTEM = r"(?:-n|--namespace)[=\s]+kube-system\b"
KUBERNETES = [
    (DENY, r"\bkubectl\b.*\bdelete\b.*" + _NS_KUBE_SYSTEM,         "kubectl delete i kube-system"),
    (DENY, r"\bkubectl\b.*" + _NS_KUBE_SYSTEM + r".*\bdelete\b",   "kubectl delete i kube-system"),
    (DENY, r"\bkubectl\b.*\bdelete\b.*(?:\s-A\b|--all-namespaces\b)", "kubectl delete över alla namespaces träffar kube-system"),
    (DENY, r"\bkubectl\b.*\bdelete\b\s+(?:nodes?|no)\b",           "kubectl delete node tar bort en nod ur klustret"),
    (DENY, r"\bkubectl\b.*\bdelete\b\s+(?:namespaces?|ns)\b",      "kubectl delete namespace raderar allt i namespacet"),
    (DENY, r"\bk3s-uninstall\.sh\b",                               "k3s-uninstall på en server river control plane/etcd"),
    (DENY, r"\bmultipass\b\s+delete\b.*(?:\s--purge\b|\s-p\b)",   "multipass delete --purge utanför destroy-skriptet"),
    (DENY, r"\bmultipass\b\s+purge\b",                             "multipass purge raderar VM:ar permanent"),
    (DENY, r"\bkubectl\b.*\bconfig\b\s+view\b.*--raw\b",           "kubectl config view --raw skriver ut kubeconfig med klientnyckel"),
    (DENY, r"\bkubectl\b(?=.*\bget\b)(?=.*\bsecrets?(?:\.v1)?(?:\s|/|$))(?=.*(?:\s-o|--output)[=\s]*(?:ya?ml|json|jsonpath|go-template|template|custom-columns))",
                                                                   "kubectl get secret -o yaml/json/jsonpath läser ut hemligheter"),
    (ASK,  r"\bkubectl\b.*\bdelete\b",                             "kubectl delete i eget namespace"),
    (ASK,  r"\bkubectl\b.*\bdrain\b",                              "drain tömmer en nod på pods"),
    (ASK,  r"\bkubectl\b.*\bcordon\b",                             "cordon stänger en nod för schemaläggning"),
    (ASK,  r"\bkubectl\b.*\bscale\b.*--replicas[=\s]+0\b",         "scale till 0 stänger tjänsten"),
    (ASK,  r"\bkubectl\b.*\brollout\b\s+restart\b",                "rollout restart startar om alla pods"),
    (ASK,  r"\bk3s-agent-uninstall\.sh\b",                         "k3s-agent-uninstall tar en worker ur klustret"),
    (ASK,  r"\bmultipass\b\s+(?:delete|stop)\b",                   "multipass delete/stop påverkar klustrets noder"),
    (ASK,  r"\bdestroy-vms\.sh\b",                                 "destroy-vms.sh river hela klustret"),
]

# kubectl apply: tillåtet för projektets egna manifest under k8s/. Allt annat
# (URL, stdin, fil utanför k8s/, --prune, kube-system) = ASK. Se
# _kubectl_apply_decision.
APPLY_ALLOWED_DIR = r"(?:^|/)k8s/"

# ansible-playbook utan --limit/-l = mot hela inventoryt = ASK. Se
# _ansible_decision. Rena läskörningar (--check, --syntax-check, --list-*)
# är alltid ALLOW.
ANSIBLE_READONLY = {"--check", "--syntax-check", "--list-tasks", "--list-hosts", "--list-tags"}

# Katastrofala filsystemoperationer = hårt stopp.
CATASTROPHIC = [
    (DENY, r":\s*\(\)\s*\{.*\|.*&.*\}",               "fork-bomb"),
    (DENY, r"\bdd\b.*\bof=/dev/(sd|nvme|disk)",       "dd skriver rått mot en disk"),
    (DENY, r"\bmkfs\b|\bwipefs\b",                     "formaterar en disk"),
    (DENY, r">\s*/dev/(sd|nvme|disk)",                "skriver rått mot en disk"),
    (DENY, r"\bchmod\b\s+-R\s+0?777\s+(/|~|\.)(\s|$)","chmod -R 777 mot rot/hemkatalog"),
    (DENY, r"\bchown\b\s+-R\b.*\s(/|~)(\s|$)",         "rekursiv chown mot rot/hemkatalog"),
]

# Destruktivt men ibland legitimt (ta bort node_modules t.ex.) = ASK.
DESTRUCTIVE = [
    (ASK,  r"\bshred\b",                              "shred förstör filer oåterkalleligt"),
    (ASK,  r"\bfind\b.*-delete\b",                    "find -delete raderar i bulk"),
    (ASK,  r"\bgit\b.*\bstash\b\s+(drop|clear)\b",    "stash drop/clear slänger sparat arbete"),
]

# Känsliga filer. Att LÄSA/kopiera ut dem = hårt stopp; att bara nämna dem = ASK.
# KUBECONFIG_FILES är kubeconfig-mönster som kubectl/helm m.fl. får referera
# (det är så de används), men som aldrig får läsas ut med cat, Read osv.
KUBECONFIG_FILES = [
    r"(^|/|\s|=)kubeconfig(\.ya?ml)?\b",
    r"(^|/)k3s\.ya?ml\b",
    r"(^|/)\.kube/config\b",
]
K3S_SECRETS = [
    r"/var/lib/rancher/k3s/server/(token|node-token|agent-token)\b",
    r"/var/lib/rancher/k3s/server/(tls|cred)/",
    r"/etc/rancher/k3s/config\.ya?ml\b",   # innehåller join-token på noderna
]
SENSITIVE = [
    r"(?<![\w.])\.env(\.[\w-]+)?\b",
    r"\bid_(rsa|ed25519|ecdsa)\b",
    r"\.pem$|\.pem\b", r"\.key$|\.key\b", r"\.p12\b", r"\.pfx\b",
    r"(^|/)\.ssh/", r"(^|/)\.aws/credentials", r"(^|/)\.gcloud/",
    r"\bsecrets?/", r"\bcredentials\.json\b", r"service[-_]account.*\.json",
    r"(^|/)\.pgpass\b", r"(^|/)\.netrc\b", r"\.env\.local\b",
] + KUBECONFIG_FILES + K3S_SECRETS
READ_VERBS = {"cat", "less", "more", "head", "tail", "bat", "cp", "scp",
              "rsync", "curl", "wget", "base64", "xxd", "od", "strings",
              "tee", "grep", "awk", "sed", "nano", "vim", "vi", "code"}
# Program som legitimt tar en kubeconfig som argument/miljövariabel.
KUBECONFIG_USERS = {"kubectl", "helm", "k9s", "kustomize", "ansible-playbook", "ansible"}

# Självskydd - agenten får inte skriva om sitt eget skyddsnät.
SELF_PROTECT = [
    r"\.claude/hooks(?:/|$)", r"\.claude/settings(\.local)?\.json\b",
]
# ...inte heller via Bash. Reagerar bara när MÅLET är en hook-fil: redirect-mål
# (inte 2>/dev/null), destinationen för cp/mv/install/rsync/ln, alla argument
# till tee/rm/chmod/chown/truncate/patch/shred/dd, sed -i, eller python -c.
DEST_VERBS = {"cp", "mv", "install", "rsync", "ln"}
INPLACE_VERBS = {"tee", "truncate", "dd", "chmod", "chown", "rm", "patch", "shred"}
SCRIPT_VERBS = {"python", "python3", "perl", "ruby", "node"}

# Bonus (överkurs): direkt e-postutskick blockeras och styrs om till verktyget
# safe_email, som kräver en 4-siffrig kod. Vårt egna verktyg släpps igenom.
EMAIL_SINK = [
    r"gmail\.googleapis\.com", r"\bsendmail\b", r"\bmutt\b\s+-s",
    r"\bmail\b\s+-s", r"\bsmtplib\b", r"\bmsmtp\b",
]
SAFE_EMAIL_TOOL = re.compile(r"safe_email", re.I)
EMAIL_TOOL = re.compile(r"(?i)(gmail|outlook|mail).*send|send.*mail|smtp")

# För dashboarden (app/build.py): regellistor med namn, plus beskrivning av
# de regler som är funktioner i stället för regex.
RULE_SETS = [
    ("Git-historik", GIT_REWRITE),
    ("Produktion och deploy", PROD_AND_DEPLOY),
    ("Kubernetes, k3s och Multipass", KUBERNETES),
    ("Katastrofalt", CATASTROPHIC),
    ("Destruktivt", DESTRUCTIVE),
]
POLICY_NOTES = [
    (DENY, "Läsa/kopiera ut en känslig fil (.env, nycklar, kubeconfig, k3s-token) med cat, grep, scp, curl, redirect ... eller via Read-verktyget"),
    (ASK,  "Kommando som bara nämner en känslig fil utan att läsa ut den"),
    (ALLOW, "kubectl/helm/ansible får referera kubeconfig via --kubeconfig eller KUBECONFIG="),
    (DENY, "rm -r mot /, ~, . eller * (katastrofalt mål)"),
    (ASK,  "rm -r mot en specifik katalog"),
    (ALLOW, "kubectl apply -f med fil under k8s/"),
    (ASK,  "kubectl apply med --prune, URL, stdin (-f -), fil utanför k8s/, utan -f, eller mot kube-system"),
    (ASK,  "ansible-playbook utan --limit/-l (hela inventoryt); --check/--syntax-check/--list-* är alltid tillåtna"),
    (DENY, "Skriva till .claude/hooks/ eller .claude/settings.json via Write/Edit eller Bash när målet är en hook-fil (redirect-mål, cp/mv-destination, tee, sed -i, rm, python -c). 2>/dev/null och läsning är tillåtet"),
    (DENY, "kubectl config view --raw samt kubectl get secret -o yaml/json/jsonpath (läser ut hemligheter)"),
    (ALLOW, "Omslag skalas bort innan bedömning: sudo -u x, env, nice -n, nohup, time, timeout N, script -q fil, script -c, xargs -n, command"),
    (DENY, "Skicka e-post direkt (gmail-API, sendmail, smtplib) eller via andra mail-verktyg än safe_email"),
    (ALLOW, "Inbäddade kommandon (ssh host \"...\", multipass exec vm -- ..., kubectl exec pod -- sh -c \"...\", bash -c \"...\") packas upp och det inre kommandot bedöms med samma regler"),
]


# ---------------------------------------------------------------------------
# MOTOR - generell logik, rörs sällan
# ---------------------------------------------------------------------------

_SEPS = re.compile(r"\s*(?:\|\||&&|\||;|&)\s*")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Omslag som kör ett annat kommando: (flaggor som tar ett argument, antal
# positionella argument före själva kommandot). "timeout 30 cmd" har 1
# positionellt (tiden), "script -q /dev/null cmd" har 1 (typescript-filen).
_WRAPPER_SPEC = {
    "sudo":    ({"-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-U", "-T"}, 0),
    "doas":    ({"-u"}, 0),
    "env":     ({"-u", "-C", "-S", "--unset", "--chdir"}, 0),
    "nice":    ({"-n", "--adjustment"}, 0),
    "nohup":   (set(), 0),
    "time":    ({"-f", "-o", "--format", "--output"}, 0),
    "timeout": ({"-s", "-k", "--signal", "--kill-after"}, 1),
    "script":  ({"-F", "-t", "-E", "-T", "-c"}, 1),
    "xargs":   ({"-I", "-n", "-P", "-d", "-L", "-s", "-E", "-a", "-J", "-R", "-S"}, 0),
    "stdbuf":  ({"-i", "-o", "-e"}, 0),
    "command": (set(), 0),
}
# Redirect-mål i en rå kommandosträng: "> fil", ">> fil", "2> fil", "&> fil".
# Fd-dubbleringar (2>&1, >&2) filtreras bort.
_REDIRECT = re.compile(r"(?<![<>])(?:\d*>>?|&>>?)\s*([^\s|&;<>]+)")
_SHELLS = {"sh", "bash", "zsh", "dash", "ash"}
# ssh-flaggor som tar ett argument (så vi hittar rätt host-token)
_SSH_OPTS_WITH_ARG = {"-i", "-p", "-l", "-o", "-F", "-J", "-L", "-R", "-D",
                      "-W", "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q",
                      "-S", "-w", "-B"}
_MAX_UNWRAP_DEPTH = 5


def _worse(a, b):
    return a if _RANK[a[0]] >= _RANK[b[0]] else b


def _split_top_level(command):
    """Dela på | || ; & && men bara utanför citat, och inte i 2>&1 / &>."""
    parts, buf, i, n = [], [], 0, len(command)
    quote = None
    while i < n:
        ch = command[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue
        if ch == ";" or ch == "|":
            parts.append("".join(buf))
            buf = []
            i += 2 if command[i:i + 2] == "||" else 1
            continue
        if ch == "&":
            prev = command[i - 1] if i > 0 else ""
            nxt = command[i + 1] if i + 1 < n else ""
            if prev in "><" or nxt == ">":      # 2>&1, &>, <&
                buf.append(ch)
                i += 1
                continue
            parts.append("".join(buf))
            buf = []
            i += 2 if nxt == "&" else 1
            continue
        buf.append(ch)
        i += 1
    if quote:
        raise ValueError("obalanserade citat")
    parts.append("".join(buf))
    return parts


def _sub_commands(command):
    """Dela upp en shell-rad i delkommandon (kring | && || ; &)."""
    try:
        raw_parts = _split_top_level(command)
    except ValueError:
        raw_parts = _SEPS.split(command)
    out = []
    for part in raw_parts:
        part = part.strip()
        if not part:
            continue
        try:
            tokens = shlex.split(part)
        except ValueError:
            tokens = part.split()
        out.append((part, _strip_wrappers(tokens)))
    return out


def _strip_wrappers(tokens):
    """Skala bort miljövariabler (KUBECONFIG=... kubectl) och omslag med
    deras flaggor och positionella argument (timeout 30 cmd, sudo -u root cmd,
    script -q /dev/null cmd). "script -c 'cmd' fil" ger cmd:s tokens."""
    while tokens:
        if _ENV_ASSIGN.match(tokens[0]):
            tokens = tokens[1:]
            continue
        name = os.path.basename(tokens[0])
        if name not in _WRAPPER_SPEC:
            break
        with_arg, positional = _WRAPPER_SPEC[name]
        i, script_cmd = 1, None
        while i < len(tokens) and tokens[i].startswith("-") and tokens[i] != "--":
            flag = tokens[i]
            if name == "script" and flag == "-c" and i + 1 < len(tokens):
                script_cmd = tokens[i + 1]          # Linux: script -c "cmd" fil
                i += 2
            elif flag in with_arg and i + 1 < len(tokens):
                i += 2
            else:
                i += 1                              # -q, -E, -n1, --foreground, nice -10
        if i < len(tokens) and tokens[i] == "--":
            i += 1
        if script_cmd is not None:
            try:
                return _strip_wrappers(shlex.split(script_cmd))
            except ValueError:
                return _strip_wrappers(script_cmd.split())
        tokens = tokens[i + positional:]
    return tokens


def _redirect_targets(raw):
    return [m for m in _REDIRECT.findall(raw) if not m.startswith("&")]


def _expand(token, cwd):
    """Tolka en relativ sökväg mot ett cd tidigare på raden."""
    if cwd and token and not token.startswith(("-", "/", "~", "$")):
        return os.path.normpath(os.path.join(cwd, token))
    return token


def _track_cd(tokens, cwd):
    """Uppdatera arbetskatalogen om delkommandot är cd/pushd."""
    if _prog(tokens) not in ("cd", "pushd"):
        return cwd
    target = next((t for t in tokens[1:] if not t.startswith("-")), None)
    if target is None or target == "-":
        return None
    if target.startswith(("/", "~", "$")):
        return target
    return os.path.normpath(os.path.join(cwd or "", target))


def _writes_out(raw):
    """Finns en redirect till något annat än /dev/null eller en fd?"""
    return any(t != "/dev/null" for t in _redirect_targets(raw))


def _match_list(text, rules):
    result = (ALLOW, "")
    for level, pattern, reason in rules:
        if re.search(pattern, text, re.IGNORECASE):
            result = _worse(result, (level, reason))
    return result


def _prog(tokens):
    return os.path.basename(tokens[0]) if tokens else ""


def _flag_values(tokens, names):
    """Värden för flaggor: -f x, -f=x, --filename=x, --filename x."""
    vals = []
    for i, t in enumerate(tokens):
        for name in names:
            if t == name and i + 1 < len(tokens):
                vals.append(tokens[i + 1])
            elif t.startswith(name + "="):
                vals.append(t[len(name) + 1:])
    return vals


def _rm_decision(tokens):
    if _prog(tokens) != "rm":
        return (ALLOW, "")
    flags = "".join(t[1:] for t in tokens[1:] if t.startswith("-") and not t.startswith("--"))
    long_flags = [t for t in tokens[1:] if t.startswith("--")]
    recursive = "r" in flags or "R" in flags or "--recursive" in long_flags
    if not recursive:
        return (ALLOW, "")
    targets = [t for t in tokens[1:] if not t.startswith("-")]
    catastrophic = {"/", "~", "$HOME", "${HOME}", ".", "..", "*", "/*", "~/*", "./*"}
    for t in targets:
        norm = t.rstrip("/")
        if t in catastrophic or norm in ("", "/", "~") or os.path.expanduser("~") == norm:
            return (DENY, "rm -r mot katastrofalt mål (" + t + ")")
    return (ASK, "rm -r kan radera mycket - bekräfta målet först")


def _kubectl_apply_decision(tokens):
    """kubectl apply: ALLOW bara för -f/-k med sökväg under k8s/ och inga
    riskflaggor. Allt annat = ASK."""
    if _prog(tokens) != "kubectl" or "apply" not in tokens:
        return (ALLOW, "")
    ns = _flag_values(tokens, ("-n", "--namespace"))
    if "kube-system" in ns:
        return (ASK, "kubectl apply mot kube-system")
    if any(t == "--prune" or t.startswith("--prune=") for t in tokens):
        return (ASK, "kubectl apply --prune kan radera resurser")
    files = _flag_values(tokens, ("-f", "--filename", "-k", "--kustomize"))
    if not files:
        return (ASK, "kubectl apply utan -f/-k")
    for f in files:
        if f == "-":
            return (ASK, "kubectl apply från stdin")
        if re.match(r"https?://", f, re.IGNORECASE):
            return (ASK, "kubectl apply från URL")
        if ".." in f or not re.search(APPLY_ALLOWED_DIR, f):
            return (ASK, "kubectl apply mot fil utanför k8s/ (" + f + ")")
    return (ALLOW, "")


def _ansible_decision(tokens):
    if _prog(tokens) != "ansible-playbook":
        return (ALLOW, "")
    if any(t in ANSIBLE_READONLY for t in tokens):
        return (ALLOW, "")
    if any(t == "-l" or t.startswith("--limit") for t in tokens):
        return (ALLOW, "")
    return (ASK, "ansible-playbook mot hela inventoryt - bekräfta")


def _protected(text):
    return any(re.search(p, text) for p in SELF_PROTECT)


def _self_protect_bash(raw, tokens, cwd=None):
    """Bash-varianten av självskyddet: DENY bara när MÅLET för en skrivning
    är en hook-fil. Läsning (cat, diff, python3 test_guard.py) och
    2>/dev/null är tillåtet. Relativa sökvägar tolkas mot ett cd tidigare
    på raden, och cp/mv -t/--target-directory räknas som destination."""
    prog = _prog(tokens)
    redirects = [_expand(t, cwd) for t in _redirect_targets(raw)]
    allargs = [_expand(t, cwd) for t in tokens[1:]]
    positional = [_expand(t, cwd) for t in tokens[1:] if not t.startswith("-")]
    target_dirs = [_expand(v, cwd) for v in _flag_values(tokens, ("-t", "--target-directory"))]
    if not any(_protected(x) for x in [raw] + redirects + allargs + target_dirs):
        return (ALLOW, "")
    deny = (DENY, "agenten får inte skriva om sitt eget skyddsnät via Bash")
    if any(_protected(t) for t in redirects):
        return deny
    if prog in DEST_VERBS:
        dest = target_dirs[-1] if target_dirs else (positional[-1] if positional else "")
        if _protected(dest):
            return deny
    if prog in INPLACE_VERBS and any(_protected(t) for t in allargs):
        return deny
    if prog == "sed" and any(t.startswith("-i") or t == "--in-place" for t in tokens[1:]) \
            and any(_protected(a) for a in positional):
        return deny
    if prog in SCRIPT_VERBS and any(t in ("-c", "-e") for t in tokens[1:]):
        return deny
    return (ALLOW, "")


def _sensitive_hit(text, patterns=None):
    return any(re.search(p, text, re.IGNORECASE) for p in (patterns or SENSITIVE))


def _join(tokens):
    """Bygg ihop ett inre kommando igen. Ett enda token = redan citerad sträng."""
    if not tokens:
        return None
    if len(tokens) == 1:
        return tokens[0]
    return " ".join(shlex.quote(t) if re.search(r"[\s|&;<>'\"$`]", t) else t for t in tokens)


def _unwrap(tokens):
    """Returnera det inbäddade kommandot i ssh/multipass exec/kubectl exec/sh -c,
    annars None."""
    prog = _prog(tokens)
    if prog == "ssh":
        i = 1
        while i < len(tokens) and tokens[i].startswith("-"):
            i += 2 if tokens[i] in _SSH_OPTS_WITH_ARG else 1
        return _join(tokens[i + 1:])            # tokens[i] är host
    if prog == "multipass" and len(tokens) > 2 and tokens[1] == "exec":
        if "--" in tokens:
            return _join(tokens[tokens.index("--") + 1:])
        return _join(tokens[3:])
    if prog == "kubectl" and "exec" in tokens:
        if "--" in tokens:
            return _join(tokens[tokens.index("--") + 1:])
        return None
    if prog in _SHELLS or prog == "su":
        for i, t in enumerate(tokens[1:], 1):
            if t == "-c" or (prog != "su" and t.startswith("-") and not t.startswith("--") and "c" in t[1:]):
                return tokens[i + 1] if i + 1 < len(tokens) else None
        return None
    return None


def _classify_subcommand(raw, tokens, cwd=None):
    result = (ALLOW, "")

    # katastrofalt + rm + självskydd först (starkast)
    result = _worse(result, _match_list(raw, CATASTROPHIC))
    result = _worse(result, _rm_decision(tokens))
    result = _worse(result, _self_protect_bash(raw, tokens, cwd))
    if result[0] == DENY:
        return result

    # git-historik, prod/deploy, kubernetes, destruktivt
    if _prog(tokens) == "git":
        result = _worse(result, _match_list(raw, GIT_REWRITE))
    result = _worse(result, _match_list(raw, PROD_AND_DEPLOY))
    result = _worse(result, _match_list(raw, KUBERNETES))
    result = _worse(result, _kubectl_apply_decision(tokens))
    result = _worse(result, _ansible_decision(tokens))
    result = _worse(result, _match_list(raw, DESTRUCTIVE))

    # känsliga filer: utläsning/kopiering = DENY, övrigt = ASK.
    # kubectl & co får referera kubeconfig utan att det räknas som känsligt.
    prog = _prog(tokens)
    patterns = SENSITIVE
    if prog in KUBECONFIG_USERS:
        patterns = [p for p in SENSITIVE if p not in KUBECONFIG_FILES]
    # relativa sökvägar efter "cd /var/lib/rancher/k3s/server && cat token"
    sensitive_text = raw
    if cwd:
        sensitive_text = raw + " " + " ".join(_expand(t, cwd) for t in tokens[1:])
    if _sensitive_hit(sensitive_text, patterns):
        if prog in READ_VERBS or _writes_out(raw):
            result = _worse(result, (DENY, "läser/kopierar ut en hemlighetsfil"))
        else:
            result = _worse(result, (ASK, "kommandot rör en känslig fil"))

    # bonus: direkt e-postutskick
    if any(re.search(p, raw, re.IGNORECASE) for p in EMAIL_SINK):
        result = _worse(result, (DENY, "skicka e-post via verktyget safe_email (4-siffrig kod) i stället"))

    return result


def _check_bash(command, depth=0):
    # Vissa katastrofala mönster (fork-bomb m.fl.) innehåller separatorer och
    # skulle styckas sönder av uppdelningen nedan - kör dem mot hela raden först.
    result = _match_list(command, CATASTROPHIC)
    if result[0] == DENY:
        return result
    cwd = None  # följer cd/pushd så att relativa sökvägar bedöms rätt
    for raw, tokens in _sub_commands(command):
        result = _worse(result, _classify_subcommand(raw, tokens, cwd))
        cwd = _track_cd(tokens, cwd)
        if result[0] == DENY:
            break
        # packa upp inbäddat kommando och bedöm det med samma regler
        inner = _unwrap(tokens) if depth < _MAX_UNWRAP_DEPTH else None
        if inner:
            level, reason = _check_bash(inner, depth + 1)
            if level != ALLOW:
                result = _worse(result, (level, "inbäddat kommando: " + reason))
            if result[0] == DENY:
                break
    return result


def _check_file(path, writing):
    if not path:
        return (ALLOW, "")
    if writing and any(re.search(p, path) for p in SELF_PROTECT):
        return (DENY, "agenten får inte skriva om sitt eget skyddsnät (" + path + ")")
    if _sensitive_hit(path):
        return (DENY, ("skriver till" if writing else "läser") + " en känslig fil (" + path + ")")
    return (ALLOW, "")


def _is_email_tool(tool):
    return bool(EMAIL_TOOL.search(tool)) and not SAFE_EMAIL_TOOL.search(tool)


def evaluate(tool, tool_input):
    if tool == "Bash":
        return _check_bash(tool_input.get("command", "") or "")
    if tool in ("Write", "Edit", "MultiEdit"):
        return _check_file(tool_input.get("file_path", "") or "", writing=True)
    if tool == "NotebookEdit":
        return _check_file(tool_input.get("notebook_path", "") or "", writing=True)
    if tool == "Read":
        return _check_file(tool_input.get("file_path", "") or "", writing=False)
    if _is_email_tool(tool):
        return (DENY, "e-post ska skickas via safe_email (kräver 4-siffrig kod), inte via " + tool)
    return (ALLOW, "")


def audit(event, tool, decision, reason):
    try:
        line = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session": event.get("session_id", ""),
            "tool": tool,
            "decision": decision,
            "reason": reason,
            "input": event.get("tool_input", {}),
        }
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")
    except OSError:
        pass  # loggning får aldrig sänka en tool-call


def respond(decision, reason):
    if decision == ALLOW:
        sys.exit(0)  # skriv inget -> normalt behörighetsflöde tar över
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False))
    sys.exit(0)


def main():
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(0)  # kan inte bedöma - blockera inte normal drift
    tool = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    decision, reason = evaluate(tool, tool_input)
    if decision != ALLOW:
        audit(event, tool, decision, reason)
    respond(decision, reason)


if __name__ == "__main__":
    main()
