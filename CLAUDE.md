# CLAUDE.md - regler för hw8-k3s

Homework-08 i AI-utbildningen: ett k3s-kluster med 3 control-plane-noder och
3 worker-noder som Multipass-VM:ar på en MacBook Air M3 (16 GB RAM). Ingen nod
har dubbla roller. Planen finns i `PLAN.md`.

## Arbetsregler

1. **Allt levereras som skript och Ansible-playbook.** Ingenting görs manuellt,
   varken i VM:arna eller i klustret. Hela kedjan ska gå från noll med
   `infra/create-vms.sh` och `ansible-playbook site.yml`, och rivas med
   `infra/destroy-vms.sh`. Enda undantaget är raden i laptopens `/etc/hosts`
   för `guard.local`, som ligger utanför VM:ar och kluster.
2. **Keep it simple.** Inget k3s-ansible-repo, inga roller i onödan, inga
   externa Ansible-collections. Ett tydligt `ansible/site.yml`.
3. **Säkerhetsnätet är alltid aktivt.** `.claude/hooks/guard.py` körs som
   PreToolUse-hook på varje tool-call via `.claude/settings.json`. Det får
   aldrig stängas av, kringgås eller försvagas.
4. **Hook-filerna får inte ändras av agenten.** Guarden DENY:ar skrivningar
   till `.claude/hooks/` och `.claude/settings.json`. Förslag på nya versioner
   skrivs till `.claude/hooks-proposed/`. Magnus granskar och kopierar själv
   över dem. Agenten kopierar aldrig, inte heller via Bash.
5. **Hemligheter skrivs aldrig ut.** Kubeconfig används via
   `kubectl --kubeconfig kubeconfig ...` eller `KUBECONFIG=./kubeconfig`,
   aldrig med `cat` eller Read. Join-token hanteras med `no_log` i Ansible
   och läses aldrig ut på laptopen.
6. **Endast vanliga bindestreck.** Alla filer i projektet använder bara
   bindestreck (-), aldrig tankstreck (varken kort eller långt). Gäller kod,
   kommentarer, YAML, Markdown och HTML.
7. **Kommandon körs från projektroten** om inget annat sägs. Ansible körs från
   `ansible/` där `ansible.cfg` pekar på det genererade `inventory.ini`.
8. **Commit bara på uppmaning.** Inget pushas eller committas utan att Magnus
   ber om det.

## Layout

```
infra/       create-vms.sh, destroy-vms.sh, cloud-init.yaml (mall)
ansible/     ansible.cfg, group_vars/all.yml, site.yml, inventory.ini (genereras)
k8s/         hello-world.yaml, guard-dashboard.yaml, deploy-dashboard.sh
app/         template.html, build.py, index.html (genereras)
.claude/     hooks/ (guard + tester, skyddade), hooks-proposed/ (staging)
kubeconfig   hämtas av playbooken, gitignored
```

## Kluster

- VM: servrar 2 CPU / 1.5 GB, workers 1 CPU / 1.5 GB, Ubuntu 24.04 LTS.
- Namn: `server1..3` (grupp `servers`), `agent1..3` (grupp `agents`).
- server1 startar med `cluster-init` (inbäddad etcd), server2/3 joinar,
  sedan agents.
- Servrarna taintas `CriticalAddonsOnly=true:NoExecute` via k3s config så att
  vanliga pods bara hamnar på workers.
