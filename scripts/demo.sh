#!/usr/bin/env bash
# One-command tour of wifipilot. Touches no radio: the simulated neighbourhood is
# driven through the real pipeline (scanner → planner → attacks → cracker → report).
#
#   ./scripts/demo.sh          # CLI campaign
#   ./scripts/demo.sh web      # web UI in simulation mode
set -euo pipefail

cd "$(dirname "$0")/.."
PY="${PY:-python3}"

if ! $PY -c "import wifipilot" 2>/dev/null; then
  echo "wifipilot is not importable — run: pip install -e ." >&2
  exit 1
fi

if [[ "${1:-}" == "web" ]]; then
  echo "Starting the web UI in simulation mode (Ctrl+C to stop)…"
  exec $PY -m wifipilot --demo web --host 127.0.0.1 --port 8787 --open
fi

echo "wifipilot simulation tour"
echo "  1/3 dependency status"
$PY -m wifipilot tools | tail -n 12 || true
echo
echo "  2/3 discovery + scoring (10 simulated access points)"
echo "  3/3 AI-planned campaign (deterministic planner if Ollama is not running)"
echo
exec $PY -m wifipilot --demo --no-color demo
