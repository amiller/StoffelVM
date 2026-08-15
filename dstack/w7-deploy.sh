#!/bin/bash
# W7 pod deploy. Usage: w7-deploy.sh <image-ref-with-digest> <measurements-csv> [bootnode-only]
# Deploys standing bootnode (stoffel-node) + 4 party tenants (stoffel-p0..p3),
# all attested + egress:true (shared tee-egress bridge for QUIC party<->bootnode).
set -e
set -a; . ~/projects/oauth3-apps/.staging-env; set +a
IMAGE=$1; MEAS=$2; MODE=${3:-all}
TOKEN=${STOFFEL_AUTH_TOKEN:?set STOFFEL_AUTH_TOKEN to the committee registration secret}
BOOT_CONTAINER=tee-image-stoffel-node-attested

deploy() {
  name=$1; shift
  curl -sm 60 -X POST "$WEBHOST_STAGING/_api/projects" \
    -H "Authorization: Bearer $TEE_DAEMON_TOKEN" -H "Content-Type: application/json" \
    -d "$1" | head -c 300; echo " <= $name"
}

common_env() {
  # NO_PROXY is mandatory: egress:true makes the daemon inject
  # ALL_PROXY=socks5://egress-vpn:1080, and the reqwest in dcap-qvl is built
  # without the socks feature, so the DCAP collateral fetch fails and the party
  # exits 13 before it ever reaches the bootnode. See RESUME "W7 pod bring-up".
  cat <<EOF
"STOFFEL_N_PARTIES":"4","STOFFEL_THRESHOLD":"1",
"STOFFEL_HTTP_ADDR":"0.0.0.0:8090",
"STOFFEL_ATTESTATION_MODE":"dstack",
"STOFFEL_DSTACK_SOCKET":"/run/broker/dstack.sock",
"STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS":"$MEAS",
"STOFFEL_AUTH_TOKEN":"$TOKEN",
"NO_PROXY":"pccs.phala.network,api.trustedservices.intel.com",
"no_proxy":"pccs.phala.network,api.trustedservices.intel.com",
"RUST_LOG":"stoffel::attestation=debug,info"
EOF
}

echo "== deploy bootnode (stoffel-node) =="
deploy stoffel-node "{\"name\":\"stoffel-node\",\"runtime\":\"image\",\"mode\":\"attested\",
 \"image\":\"$IMAGE\",\"image_port\":8090,\"egress\":true,
 \"volumes\":[{\"name\":\"stoffel-node-data\",\"mount\":\"/data\"}],
 \"env\":{\"STOFFEL_ROLE\":\"bootnode\",\"STOFFEL_BIND_ADDR\":\"0.0.0.0:9000\",$(common_env)}}"

[ "$MODE" = "bootnode-only" ] && exit 0
sleep 10

for i in 0 1 2 3; do
  echo "== deploy party $i (stoffel-p$i) =="
  deploy stoffel-p$i "{\"name\":\"stoffel-p$i\",\"runtime\":\"image\",\"mode\":\"attested\",
   \"image\":\"$IMAGE\",\"image_port\":8090,\"egress\":true,
   \"env\":{\"STOFFEL_ROLE\":\"party\",\"STOFFEL_PARTY_ID\":\"$i\",
    \"STOFFEL_BIND_ADDR\":\"0.0.0.0:9000\",
    \"STOFFEL_BOOTSTRAP_ADDR\":\"$BOOT_CONTAINER:9000\",
    \"STOFFEL_ADVERTISE_HOST\":\"tee-image-stoffel-p$i-attested\",$(common_env)}}"
done
echo DEPLOY-DONE
