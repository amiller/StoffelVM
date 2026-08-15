#!/bin/bash
# W7 parties-only deploy. Usage: w7-parties.sh <image-ref> <measurements-csv>
set -e
set -a; . ~/projects/oauth3-apps/.staging-env; set +a
IMAGE=$1; MEAS=$2
TOKEN=${STOFFEL_AUTH_TOKEN:?set STOFFEL_AUTH_TOKEN to the committee registration secret}
BOOT_CONTAINER=tee-image-stoffel-node-attested
common_env() {
  cat <<EOG
"STOFFEL_N_PARTIES":"4","STOFFEL_THRESHOLD":"1",
"STOFFEL_HTTP_ADDR":"0.0.0.0:8090",
"STOFFEL_ATTESTATION_MODE":"dstack",
"STOFFEL_DSTACK_SOCKET":"/run/broker/dstack.sock",
"STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS":"$MEAS",
"STOFFEL_AUTH_TOKEN":"$TOKEN",
"NO_PROXY":"pccs.phala.network,api.trustedservices.intel.com",
"no_proxy":"pccs.phala.network,api.trustedservices.intel.com",
"STOFFEL_HOLD_OPEN":"true",
"RUST_LOG":"stoffel::attestation=debug,info"
EOG
}
for i in 0 1 2 3; do
  echo "== deploy party $i =="
  curl -sm 60 -X POST "$WEBHOST_STAGING/_api/projects" \
    -H "Authorization: Bearer $TEE_DAEMON_TOKEN" -H "Content-Type: application/json" \
    -d "{\"name\":\"stoffel-p$i\",\"runtime\":\"image\",\"mode\":\"attested\",
     \"image\":\"$IMAGE\",\"image_port\":8090,\"egress\":true,
     \"env\":{\"STOFFEL_ROLE\":\"party\",\"STOFFEL_PARTY_ID\":\"$i\",
      \"STOFFEL_BIND_ADDR\":\"0.0.0.0:9000\",
      \"STOFFEL_BOOTSTRAP_ADDR\":\"$BOOT_CONTAINER:9000\",
      \"STOFFEL_ADVERTISE_HOST\":\"tee-image-stoffel-p$i-attested\",$(common_env)}}" \
    -o /dev/null -w "  http=%{http_code}\n"
done
echo PARTIES-DONE
