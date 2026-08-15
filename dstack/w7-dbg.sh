#!/bin/bash
# Deploy p0 on the debug image (serves its captured stderr on /node.log after exit).
set -e
set -a; . ~/projects/oauth3-apps/.staging-env; set +a
IMAGE=$1; MEAS=$2
TOKEN=${STOFFEL_AUTH_TOKEN:?set STOFFEL_AUTH_TOKEN to the committee registration secret}
NP='"NO_PROXY":"pccs.phala.network,api.trustedservices.intel.com","no_proxy":"pccs.phala.network,api.trustedservices.intel.com"'
curl -sm 90 -X POST "$WEBHOST_STAGING/_api/projects" -H "Authorization: Bearer $TEE_DAEMON_TOKEN" \
 -H "Content-Type: application/json" -d "{\"name\":\"stoffel-p0\",\"runtime\":\"image\",\"mode\":\"attested\",
  \"image\":\"$IMAGE\",\"image_port\":8090,\"egress\":true,
  \"env\":{\"STOFFEL_ROLE\":\"party\",\"STOFFEL_PARTY_ID\":\"0\",\"STOFFEL_BIND_ADDR\":\"0.0.0.0:9000\",
   \"STOFFEL_BOOTSTRAP_ADDR\":\"tee-image-stoffel-node-attested:9000\",
   \"STOFFEL_ADVERTISE_HOST\":\"tee-image-stoffel-p0-attested\",
   \"STOFFEL_N_PARTIES\":\"4\",\"STOFFEL_THRESHOLD\":\"1\",\"STOFFEL_HTTP_ADDR\":\"0.0.0.0:8090\",
   \"STOFFEL_ATTESTATION_MODE\":\"dstack\",\"STOFFEL_DSTACK_SOCKET\":\"/run/broker/dstack.sock\",
   \"STOFFEL_ATTESTATION_ALLOWED_MEASUREMENTS\":\"$MEAS\",\"STOFFEL_AUTH_TOKEN\":\"$TOKEN\",
   \"RUST_LOG\":\"stoffel::attestation=debug,info\",\"STOFFEL_HOLD_OPEN\":\"true\",$NP}}" -o /dev/null -w "deploy http=%{http_code}\n"
echo "waiting for the node to exit and busybox to serve the log..."
for i in $(seq 1 40); do
  L=$(curl -sm 8 "$WEBHOST_STAGING/stoffel-p0/node.log" 2>/dev/null)
  case "$L" in *StoffelVM*) echo "$L"; exit 0;; esac
  sleep 10
done
echo "no log after 400s"
