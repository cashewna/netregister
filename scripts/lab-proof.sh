#!/bin/sh
# Isolated two-scan proof. Runs inside the scanner container on the compose
# bridge network only. No host LAN traffic is generated.
set -eu

CFG=${NETREGISTER_CONFIG:-/etc/netregister.toml}
DB=/data/netregister.db
BEFORE=/tmp/inventory-before.tsv
AFTER=/tmp/inventory-after.tsv
EXPECTED_IPS=/tmp/expected-ips.txt
ACTUAL_IPS=/tmp/actual-ips.txt

# Timestamps resolving to one second mean we wait before the second scan.
SECOND_SCAN_DELAY=${SECOND_SCAN_DELAY:-2}

fail() {
    echo "PROOF FAILED: $*" >&2
    exit 1
}

# numeric field from a `key=value key=value` scan summary
field() {
    printf '%s\n' "$1" | sed -n "s/.* $2=\([0-9][0-9]*\).*/\1/p"
}

rm -f "$DB" "$DB-journal" "$BEFORE" "$AFTER"

echo "=== allow-list refusal: 10.99.0.0/24 is not in scanner.allowed_networks ==="
set +e
netregister --config "$CFG" scan --network 10.99.0.0/24 2>/tmp/refusal.txt
REFUSAL_STATUS=$?
set -e
if [ "$REFUSAL_STATUS" -ne 2 ]; then
    fail "expected allow-list refusal exit code 2, got $REFUSAL_STATUS"
fi
echo "refused as expected (exit 2): $(cat /tmp/refusal.txt)"
if [ -f "$DB" ]; then
    fail "refused scan still created the database"
fi

# The compose healthchecks wait for the device listeners before this container
# starts; no fixed startup sleep is needed here.

echo ""
echo "=== scan 1 ==="
SCAN1=$(netregister --config "$CFG" scan --network 172.28.77.0/28)
echo "$SCAN1"
STATS1=$(netregister --config "$CFG" stats --format tsv)
HOSTS1=$(printf '%s\n' "$STATS1" | cut -f1)
PORTS1=$(printf '%s\n' "$STATS1" | cut -f2)
netregister --config "$CFG" list --format tsv > "$BEFORE"
echo "hosts_row_count_after_scan1=$HOSTS1"
echo "open_port_row_count_after_scan1=$PORTS1"
echo "--- inventory after scan 1 ---"
netregister --config "$CFG" list

echo ""
echo "=== waiting ${SECOND_SCAN_DELAY}s so last_seen can advance ==="
sleep "$SECOND_SCAN_DELAY"

echo ""
echo "=== scan 2 ==="
SCAN2=$(netregister --config "$CFG" scan --network 172.28.77.0/28)
echo "$SCAN2"
STATS2=$(netregister --config "$CFG" stats --format tsv)
HOSTS2=$(printf '%s\n' "$STATS2" | cut -f1)
PORTS2=$(printf '%s\n' "$STATS2" | cut -f2)
netregister --config "$CFG" list --format tsv > "$AFTER"
echo "hosts_row_count_after_scan2=$HOSTS2"
echo "open_port_row_count_after_scan2=$PORTS2"
echo "--- inventory after scan 2 ---"
netregister --config "$CFG" list

echo ""
echo "=== assertions ==="

[ "$(field "$SCAN1" discovered)" -eq 4 ] || fail "scan 1 should discover 4 hosts"
[ "$(field "$SCAN1" inserted)" -eq 4 ] || fail "scan 1 should insert 4 hosts"
[ "$(field "$SCAN2" discovered)" -eq 4 ] || fail "scan 2 should discover 4 hosts"
[ "$(field "$SCAN2" inserted)" -eq 0 ] || fail "scan 2 must not insert rows"
[ "$(field "$SCAN2" updated)" -eq 4 ] || fail "scan 2 should update all 4 rows"
[ "$(field "$SCAN2" unchanged)" -eq 0 ] || fail "scan 2 left a row unchanged"
[ "$HOSTS1" -eq 4 ] || fail "expected 4 host rows after scan 1, got $HOSTS1"
[ "$HOSTS2" -eq 4 ] || fail "expected 4 host rows after scan 2, got $HOSTS2"
[ "$HOSTS1" -eq "$HOSTS2" ] || fail "host row count changed between scans"
[ "$(wc -l < "$BEFORE")" -eq 4 ] || fail "inventory file after scan 1 does not have 4 rows"
[ "$(wc -l < "$AFTER")" -eq 4 ] || fail "inventory file after scan 2 does not have 4 rows"

cut -f2 "$BEFORE" | sort > "$ACTUAL_IPS"
printf '172.28.77.1\n172.28.77.2\n172.28.77.3\n172.28.77.4\n' | sort > "$EXPECTED_IPS"
if ! diff -u "$EXPECTED_IPS" "$ACTUAL_IPS"; then
    fail "discovered IPs are not exactly the router plus the three labelled containers"
fi

[ "$(awk -F'\t' '$2=="172.28.77.1"{print $3}' "$BEFORE")" = "edge-router" ] || fail "router metadata missing"
[ "$(awk -F'\t' '$2=="172.28.77.2"{print $3}' "$BEFORE")" = "lab-nas" ] || fail "nas metadata missing"
[ "$(awk -F'\t' '$2=="172.28.77.3"{print $3}' "$BEFORE")" = "lab-printer" ] || fail "printer metadata missing"
[ "$(awk -F'\t' '$2=="172.28.77.4"{print $3}' "$BEFORE")" = "lab-camera" ] || fail "camera metadata missing"
[ "$(awk -F'\t' '$2=="172.28.77.2"{print $8}' "$BEFORE")" = "8080" ] || fail "nas open port not detected"
[ "$(awk -F'\t' '$2=="172.28.77.3"{print $8}' "$BEFORE")" = "9100" ] || fail "printer open port not detected"
[ "$(awk -F'\t' '$2=="172.28.77.4"{print $8}' "$BEFORE")" = "80" ] || fail "camera open port not detected"
[ "$PORTS1" -eq 3 ] || fail "expected 3 open port rows, got $PORTS1"

paste /tmp/inventory-before.tsv "$AFTER" | awk -F'\t' '
    $1 != $9 { print "MAC order changed"; exit 1 }
    $6 != $14 { print "first_seen changed"; exit 1 }
    $7 >= $15 { print "last_seen did not advance"; exit 1 }
' || fail "cross-scan comparison failed"

echo "scan1_summary: $SCAN1"
echo "scan2_summary: $SCAN2"
echo "hosts_row_count_scan1=$HOSTS1"
echo "hosts_row_count_scan2=$HOSTS2"
echo "last_seen advanced for all 4 hosts; first_seen unchanged; row count identical"
echo "PROOF OK"
