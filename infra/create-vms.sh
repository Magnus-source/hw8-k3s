#!/usr/bin/env bash
# create-vms.sh - skapar sex Multipass-VM:ar för k3s och genererar
# ansible/inventory.ini. Idempotent: VM:ar som redan finns lämnas orörda,
# inventoryt skrivs alltid om med aktuella IP-adresser.
#
#   bash infra/create-vms.sh
#
# Miljövariabler som kan överstyras:
#   SSH_PUB_KEY  sökväg till din publika nyckel (default ~/.ssh/id_ed25519.pub)
#   IMAGE        Ubuntu-release (default 24.04)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SSH_PUB_KEY="${SSH_PUB_KEY:-$HOME/.ssh/id_ed25519.pub}"
IMAGE="${IMAGE:-24.04}"
DISK="8G"
MEM="1536M"

SERVERS="server1 server2 server3"   # 2 CPU, control plane + etcd
AGENTS="agent1 agent2 agent3"       # 1 CPU, workers

TEMPLATE="$ROOT/infra/cloud-init.yaml"
RENDERED="$ROOT/infra/cloud-init.rendered.yaml"
INVENTORY="$ROOT/ansible/inventory.ini"

command -v multipass >/dev/null || { echo "multipass saknas: brew install --cask multipass" >&2; exit 1; }
[ -r "$SSH_PUB_KEY" ] || { echo "hittar ingen publik nyckel: $SSH_PUB_KEY" >&2; exit 1; }

# 1. Rendera cloud-init med nyckeln. Nyckeln läses av skriptet, inte av agenten.
PUB="$(cat "$SSH_PUB_KEY")"
sed "s|__SSH_PUB_KEY__|$PUB|" "$TEMPLATE" > "$RENDERED"

# 2. Starta VM:ar som saknas.
launch() {
  local name="$1" cpus="$2"
  if multipass info "$name" >/dev/null 2>&1; then
    echo "== $name finns redan, hoppar över"
    return
  fi
  echo "== startar $name ($cpus CPU, $MEM, $DISK, Ubuntu $IMAGE)"
  multipass launch "$IMAGE" --name "$name" --cpus "$cpus" --memory "$MEM" \
    --disk "$DISK" --cloud-init "$RENDERED" --timeout 600
}

for s in $SERVERS; do launch "$s" 2; done
for a in $AGENTS;  do launch "$a" 1; done

# 3. Hämta IP-adresser (första IPv4 per VM).
ip_of() {
  multipass info "$1" --format json | python3 -c '
import json, sys
name = sys.argv[1]
info = json.load(sys.stdin)["info"][name]
print(info["ipv4"][0])' "$1"
}

# 4. Skriv inventory.
{
  echo "# Genererad av infra/create-vms.sh $(date '+%Y-%m-%d %H:%M'). Redigera inte för hand."
  echo "[servers]"
  for s in $SERVERS; do echo "$s ansible_host=$(ip_of "$s")"; done
  echo
  echo "[agents]"
  for a in $AGENTS; do echo "$a ansible_host=$(ip_of "$a")"; done
  echo
  echo "[k3s:children]"
  echo "servers"
  echo "agents"
} > "$INVENTORY"

echo
echo "== inventory skrivet till ansible/inventory.ini"
cat "$INVENTORY"

# 5. Vänta tills ssh svarar på alla noder.
echo
echo "== väntar på ssh"
for n in $SERVERS $AGENTS; do
  ip="$(ip_of "$n")"
  for _ in $(seq 1 60); do
    if nc -z -w 2 "$ip" 22 2>/dev/null; then echo "   $n ($ip) ok"; break; fi
    sleep 2
  done
done

echo
echo "Klart. Nästa steg:  cd ansible && ansible-playbook site.yml"
