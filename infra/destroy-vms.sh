#!/usr/bin/env bash
# destroy-vms.sh - river hela klustret: tar bort och purgar alla sex VM:ar
# samt de genererade filerna (inventory, kubeconfig, renderad cloud-init).
#
#   bash infra/destroy-vms.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODES="server1 server2 server3 agent1 agent2 agent3"

echo "== tar bort VM:ar"
for n in $NODES; do
  if multipass info "$n" >/dev/null 2>&1; then
    multipass delete "$n" && echo "   $n borttagen"
  else
    echo "   $n fanns inte"
  fi
done

echo "== purgar"
multipass purge

echo "== städar genererade filer"
rm -f "$ROOT/ansible/inventory.ini" "$ROOT/kubeconfig" "$ROOT/infra/cloud-init.rendered.yaml"

echo
echo "Klart. Glöm inte att ta bort raden för guard.local i /etc/hosts:"
echo "  sudo sed -i '' '/guard.local/d' /etc/hosts"
