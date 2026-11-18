#!/usr/bin/env bash
# Analyse de démonstration contre une instance DomainExposure déjà démarrée,
# puis export des rapports HTML et PDF.
#
#   ./scripts/demo.sh exemple.fr
#
# En lançant ce script, vous attestez disposer d'une autorisation du propriétaire
# du domaine analysé ou agir dans un cadre contractuel : les consentements sont
# transmis à l'API et journalisés.

set -euo pipefail

DOMAINE="${1:-example.com}"
BASE="${BASE_URL:-http://127.0.0.1:8080}"
SORTIE="${SORTIE:-.}"

echo "→ Service : ${BASE}"
curl -fsS --noproxy '*' "${BASE}/api/health" > /dev/null || {
  echo "Le service ne répond pas. Démarrez-le avec « docker compose up -d » ou « python -m app »." >&2
  exit 1
}

echo "→ Analyse de ${DOMAINE}"
ID=$(curl -fsS --noproxy '*' -X POST "${BASE}/api/analyses" \
      -H 'content-type: application/json' \
      -d "{\"domain\":\"${DOMAINE}\",\"authorization\":true,\"passive_only\":true}" \
     | python3 -c 'import sys, json; print(json.load(sys.stdin)["id"])')

echo "→ Progression (identifiant ${ID})"
curl -sN --noproxy '*' "${BASE}/api/analyses/${ID}/stream" \
  | grep --line-buffered '^event: module_done' \
  | while read -r _; do printf '.'; done
echo

python3 - "$BASE" "$ID" <<'PY'
import json, sys, urllib.request
base, identifiant = sys.argv[1], sys.argv[2]
with urllib.request.urlopen(f"{base}/api/analyses/{identifiant}") as reponse:
    rapport = json.load(reponse)
print(f"\n{rapport['domain']} — score {rapport['score']}/100, note {rapport['grade']}\n")
for module in rapport["modules"]:
    score = module["score"] if module["score"] is not None else "--"
    print(f"  [{module['status']:7}] {module['label']:24} {score:>4}  "
          f"{len(module['findings'])} constat(s)")
PY

curl -fsS --noproxy '*' -o "${SORTIE}/rapport-${DOMAINE}.html" "${BASE}/api/analyses/${ID}/report.html"
curl -fsS --noproxy '*' -o "${SORTIE}/rapport-${DOMAINE}.pdf"  "${BASE}/api/analyses/${ID}/report.pdf"
echo
echo "→ Rapports écrits : ${SORTIE}/rapport-${DOMAINE}.html et ${SORTIE}/rapport-${DOMAINE}.pdf"
