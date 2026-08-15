#!/bin/bash
# W7 attested committee, with NO_PROXY so the DCAP collateral fetch bypasses the
# daemon-injected socks5 ALL_PROXY (reqwest here is built without socks support).
set -e
set -a; . ~/projects/oauth3-apps/.staging-env; set +a
IMAGE=$1; MEAS=$2
TOKEN=${STOFFEL_AUTH_TOKEN:?set STOFFEL_AUTH_TOKEN to the committee registration secret}
BOOT=tee-image-stoffel-node-attested
NP='"NO_PROXY":"pccs.phala.network,api.trustedservices.intel.com","no_proxy":"pccs.phala.network,api.trustedservices.intel.com"'
common="\"STOFFEL_N_PARTIES\":\"4\",\"STOFFEL_THRESHOLD\":\"1\",\"STOFFEL_HTTP_ADDR\":\"0.0.0.0:8090\",
\"STOFFEL_ATTESTATION_MODE\":\"dstack\",\"STOFFEL_DSTACK_SOCKET\":\"/run/broker/dstack.sock\",
\"STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS\":\"$MEAS\",\"STOFFEL_AUTH_TOKEN\":\"$TOKEN\",
\"RUST_LOG\":\"stoffel::attestation=debug,info\",\"STOFFEL_HOLD_OPEN\":\"true\",$NP"
post() { curl -sm 90 -X POST "$WEBHOST_STAGING/_api/projects" \
  -H "Authorization: Bearer $TEE_DAEMON_TOKEN" -H "Content-Type: application/json" \
  -d "$1" -o /dev/null -w "http=%{http_code}\n"; }

echo "== bootnode (attested, pin=$MEAS) =="
post "{\"name\":\"stoffel-node\",\"runtime\":\"image\",\"mode\":\"attested\",\"image\":\"$IMAGE\",
 \"image_port\":8090,\"egress\":true,\"volumes\":[{\"name\":\"stoffel-node-data\",\"mount\":\"/data\"}],
 \"env\":{\"STOFFEL_ROLE\":\"bootnode\",\"STOFFEL_BIND_ADDR\":\"0.0.0.0:9000\",$common}}"
until curl -sm 10 "$WEBHOST_STAGING/stoffel-node/health" | grep -q bootnode; do sleep 5; done
echo "bootnode up"
for i in 0 1 2 3; do
  echo "== party $i =="
  post "{\"name\":\"stoffel-p$i\",\"runtime\":\"image\",\"mode\":\"attested\",\"image\":\"$IMAGE\",
   \"image_port\":8090,\"egress\":true,
   \"env\":{\"STOFFEL_ROLE\":\"party\",\"STOFFEL_PARTY_ID\":\"$i\",\"STOFFEL_BIND_ADDR\":\"0.0.0.0:9000\",
    \"STOFFEL_BOOTSTRAP_ADDR\":\"$BOOT:9000\",\"STOFFEL_ADVERTISE_HOST\":\"tee-image-stoffel-p$i-attested\",$common}}"
done
echo "== polling /peers =="
for i in $(seq 1 24); do
  echo "t+$((i*10))s: $(curl -sm 10 "$WEBHOST_STAGING/stoffel-node/peers")"
  sleep 10
done
