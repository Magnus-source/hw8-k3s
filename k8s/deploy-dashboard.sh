#!/usr/bin/env bash
# deploy-dashboard.sh - bygger app/index.html och rullar ut dashboarden.
#
#   bash k8s/deploy-dashboard.sh
#
# 1. app/build.py genererar index.html från guardens regler + testkörning.
# 2. Namespace, Deployment, Service och Ingress appliceras från yaml.
# 3. ConfigMap:en med index.html skapas/uppdateras. Volymen synkas in i
#    löpande pods automatiskt, så ingen rollout restart behövs vid rebuild.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$ROOT/kubeconfig}"

echo "== bygger app/index.html"
python3 "$ROOT/app/build.py"

echo "== applicerar manifest"
kubectl apply -f "$ROOT/k8s/guard-dashboard.yaml"

echo "== uppdaterar ConfigMap"
kubectl create configmap guard-dashboard-html -n guard \
  --from-file=index.html="$ROOT/app/index.html" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "== väntar på rollout"
kubectl rollout status deploy/guard-dashboard -n guard --timeout=180s
kubectl get pods -n guard -o wide

NODE_IP="$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' \
  -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
echo
echo "Testa:   curl -H 'Host: guard.local' http://$NODE_IP/ | head -5"
echo "Browser: lägg till i /etc/hosts:   $NODE_IP guard.local"
