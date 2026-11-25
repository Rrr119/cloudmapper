#!/usr/bin/env bash
# Acceptance entry point for the internet -> sensitive resource reachability
# feature.  Verifies:
#   1. reachable paths for 3 accounts match hand-derived expectations
#      (topology doc, prepare-compatible graph.json and raw account snapshot),
#   2. security-group rule changes produce correct incremental path diffs,
#   3. the CloudMapper CLI and existing graph data format keep working.
set -euo pipefail

cd "$(dirname "$0")"
PYTHON_BIN="${PYTHON:-python3}"

FIX="tests/fixtures/reachability"
ACCOUNTS="shop,analytics,partner"

echo "==> [1/5] Refreshing the three acceptance accounts"
"$PYTHON_BIN" "$FIX/build_fixtures.py" --web

echo
echo "==> [2/5] Manual reasoning oracle (3 accounts + incremental scenarios)"
"$PYTHON_BIN" "$FIX/verify_acceptance.py"

echo
echo "==> [3/5] Unit/acceptance tests"
"$PYTHON_BIN" -m unittest tests.unit.test_reachability_acceptance -v

echo
echo "==> [4/5] CLI report for all three accounts (text)"
"$PYTHON_BIN" commands/reachability.py --accounts "$ACCOUNTS" --format text

echo
echo "==> [5/5] CLI graph compatibility + incremental state update"
for account in shop analytics partner; do
  "$PYTHON_BIN" commands/reachability.py \
    --graph "$FIX/accounts/$account/graph.json" \
    --accounts "$account" \
    --format json \
    --out "artifacts/reachability-$account.json"
  echo "  wrote artifacts/reachability-$account.json"
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
STATE="$TMP_DIR/state.json"
CHANGED_SG="$TMP_DIR/sg-shop-web.json"

"$PYTHON_BIN" commands/reachability.py --accounts "$ACCOUNTS" --state "$STATE" >/dev/null
cat > "$CHANGED_SG" <<'JSON'
{"GroupId": "sg-shop-web", "GroupName": "shop-web", "IpPermissions": []}
JSON
"$PYTHON_BIN" commands/reachability.py \
  --accounts "$ACCOUNTS" --state "$STATE" \
  --update-sg "shop=$CHANGED_SG" --format json \
  | "$PYTHON_BIN" -c '
import json, sys
payload = json.load(sys.stdin)
update = payload["updates"][0]
assert update["paths_removed_count"] == 1, update
assert update["removed_path_keys"] == [
    ["0.0.0.0/0", "web", "app", "db-orders"]
], update["removed_path_keys"]
assert update["report"]["path_keys"] == [
    ["0.0.0.0/0", "bastion", "app", "db-orders"]
], update["report"]["path_keys"]
print("  incremental CLI diff verified: web chain removed, bastion chain kept")
'

echo
echo "All acceptance checks passed."
echo " - manual reasoning: $FIX/accounts/<account>/manual_reasoning.md"
echo " - visualization:    web/reachability.html (run: $PYTHON_BIN cloudmapper.py webserver)"
