#!/bin/bash
# W7 e2e, pod-shaped: standing bootnode-only + 4 parties (n=4 t=1), attestation
# disabled (mock is CI-only by design; the TDX gate e2e happens on the pod).
# Verifies: committee forms, program runs to same result on all parties,
# /peers on the bootnode shows 4 admissions AND a rejection for a bad-token party.
set -e
ROOT=${STOFFEL_ROOT:-$HOME/stoffel-build}; BIN=$ROOT/target/release
E2E=/tmp/w7e2e
rm -rf $E2E && mkdir -p $E2E
cd $ROOT

echo "== compile demo program =="
$BIN/stoffellang -b docker/programs/demo_program.stfl -o $E2E/program.stflb
N=4; T=1; PROG=$E2E/program.stflb
export RUST_LOG=info

echo "== start standing bootnode (:9000, http :8090) =="
STOFFEL_AUTH_TOKEN=w7-e2e-token STOFFEL_HTTP_ADDR=127.0.0.1:8090 \
  $BIN/stoffel-run --bootnode --bind 127.0.0.1:9000 --n-parties $N \
  > $E2E/bootnode.log 2>&1 &
echo $! > $E2E/bootnode.pid
sleep 2

echo "== negative: party with WRONG auth token =="
STOFFEL_AUTH_TOKEN=wrong-token timeout 15 \
  $BIN/stoffel-run $PROG main --party-id 0 --bootstrap 127.0.0.1:9000 \
  --bind 127.0.0.1:9100 --n-parties $N --threshold $T --advertise 127.0.0.1:9100 \
  > $E2E/badparty.log 2>&1 || echo "(bad-token party exited nonzero as expected)"

echo "== start 4 honest parties =="
for i in 0 1 2 3; do
  STOFFEL_AUTH_TOKEN=w7-e2e-token STOFFEL_HTTP_ADDR=127.0.0.1:809$((i+1)) \
    $BIN/stoffel-run $PROG main --party-id $i --bootstrap 127.0.0.1:9000 \
    --bind 127.0.0.1:900$((i+1)) --n-parties $N --threshold $T \
    --advertise 127.0.0.1:900$((i+1)) > $E2E/party$i.log 2>&1 &
  echo $! > $E2E/party$i.pid
done

echo "== wait for all 4 parties to finish (max 180s) =="
deadline=$(( $(date +%s) + 180 ))
while [ $(date +%s) -lt $deadline ]; do
  done_ct=$(grep -l "Program returned:" $E2E/party*.log 2>/dev/null | wc -l)
  [ "$done_ct" -ge 4 ] && break
  sleep 3
done

echo "== RESULTS =="
echo "--- results per party:"; grep -H "Program returned:" $E2E/party*.log || echo "NO RESULTS"
echo "--- /peers on bootnode (should show admissions + bad-token rejection):"
curl -sm3 127.0.0.1:8090/peers; echo
echo "--- /health:"; curl -sm3 127.0.0.1:8090/health; echo
echo "--- bootnode.log admission lines:"; grep -iE "admit|reject|attest|auth" $E2E/bootnode.log | tail -8
echo "--- badparty.log tail:"; tail -3 $E2E/badparty.log
echo "== teardown =="
for f in $E2E/*.pid; do kill $(cat $f) 2>/dev/null || true; done
wait 2>/dev/null || true
echo E2E-SCRIPT-DONE
