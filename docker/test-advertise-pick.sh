#!/bin/bash
# Unit test for the advertise-address selection in entrypoint.sh.
#
# A committee tenant sits on two docker networks: its private per-project one
# and the shared bridge every party joins. Only an address on the shared network
# is reachable by a peer. Publishing the private one produces a committee that
# forms (registration reaches the bootnode) but cannot compute — peers time out
# and preprocessing dies with PartyNotFound. This test pins the selection.
set -u
cd "$(dirname "$0")"

# Pull the function under test out of entrypoint.sh so the test exercises the
# real code rather than a copy that can drift.
eval "$(sed -n '/^pick_ip_on_peer_network()/,/^}/p' entrypoint.sh)"

fail=0
check() {
  local name=$1 addrs=$2 peer=$3 want=$4 got
  # shellcheck disable=SC2317
  hostname() { echo "$addrs"; }
  got=$(pick_ip_on_peer_network "$peer" 2>/dev/null) || got="<none>"
  if [ "$got" = "$want" ]; then
    echo "ok   - $name"
  else
    echo "FAIL - $name: peer=$peer addrs='$addrs' want=$want got=$got"
    fail=1
  fi
}

# The real case: private address listed first, shared second. The old code took
# the first answer docker DNS gave and published 192.168.96.3.
check "prefers the shared network over the private one" \
  "192.168.96.3 172.28.0.4" "172.28.0.3" "172.28.0.4"

# Order must not matter — docker DNS does not define one.
check "order independent" \
  "172.28.0.4 192.168.96.3" "172.28.0.3" "172.28.0.4"

# Fault 4: the shared network is attached after the container starts, so early
# on the only address is the private one. Selecting it anyway is what stalled
# the mesh; refusing lets the caller retry until the interface is up.
check "refuses when only the private address exists yet" \
  "192.168.96.3" "172.28.0.3" "<none>"

# IPv6 entries in hostname -I must not be mistaken for candidates.
check "ignores ipv6" \
  "fe80::1 192.168.96.3 172.28.0.9" "172.28.0.3" "172.28.0.9"

# A different shared subnet must still resolve against that subnet, not 172.28.
check "matches the bootstrap subnet, not a hardcoded one" \
  "10.5.0.7 192.168.96.3" "10.5.0.1" "10.5.0.7"

# Same /16 but a different /24 is a different docker network — not a match.
check "does not accept a same-/16 different-/24 address" \
  "172.28.9.4" "172.28.0.3" "<none>"

exit $fail
