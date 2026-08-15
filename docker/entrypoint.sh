#!/bin/bash
set -e

# StoffelVM Docker Entrypoint Script
# Handles both leader and party node startup with proper coordination

validate_env() {
    if [ "${STOFFEL_ROLE}" != "client" ] && [ -z "${STOFFEL_AUTH_TOKEN:-}" ]; then
        echo "ERROR: STOFFEL_AUTH_TOKEN must be set for ${STOFFEL_ROLE} mode."
        echo "Bootnode and parties require authenticated discovery registration."
        exit 2
    fi
}

validate_env

# W7: Resolve the IP address peers should use to connect to this node.
#
# A tenant here sits on TWO docker networks: its own private per-project network
# and the shared egress bridge every committee member joins. Only the shared one
# is routable between parties. Resolving our OWN container name (the old
# STOFFEL_ADVERTISE_HOST path) asks docker DNS for a name that exists on both,
# and the order is not defined — a party that draws its private address
# advertises somewhere no peer can reach, every peer connect times out, and the
# run dies in preprocessing with PartyNotFound.
#
# The bootstrap address pins the answer: docker DNS resolves the bootnode's name
# to its address on a network WE SHARE with it, so our own address on that same
# network is the one to advertise. Pick the local address with the longest
# leading-octet match against the resolved bootstrap IP.
# The shared network is attached AFTER the container starts, so early on our
# only address is the private one. Accept a candidate only when it shares the
# peer's /24 — anything less means the shared interface isn't up yet.
pick_ip_on_peer_network() {
    local peer_ip=$1 prefix ip
    prefix=$(echo "$peer_ip" | cut -d. -f1-3)
    for ip in $(hostname -I); do
        case "$ip" in *:*) continue;; esac
        if [ "$(echo "$ip" | cut -d. -f1-3)" = "$prefix" ]; then echo "$ip"; return 0; fi
    done
    return 1
}

if [ -n "${STOFFEL_ADVERTISE_HOST:-}" ] && [ -n "${STOFFEL_BOOTSTRAP_ADDR:-}" ]; then
    bootstrap_host=$(echo "${STOFFEL_BOOTSTRAP_ADDR}" | cut -d: -f1)
    echo "Selecting advertise IP on the network shared with ${bootstrap_host}..."
    max_attempts=30
    attempt=1
    peer_ip=""
    while [ $attempt -le $max_attempts ]; do
        peer_ip=$(getent hosts "${bootstrap_host}" 2>/dev/null | awk '{print $1; exit}')
        [ -n "$peer_ip" ] && break
        echo "Attempt ${attempt}/${max_attempts}: ${bootstrap_host} not yet resolvable, waiting..."
        sleep 1
        attempt=$((attempt + 1))
    done
    if [ -z "$peer_ip" ]; then
        echo "ERROR: bootstrap host ${bootstrap_host} could not be resolved after ${max_attempts} attempts"
        exit 5
    fi
    attempt=1
    STOFFEL_ADVERTISE_IP=""
    while [ $attempt -le $max_attempts ]; do
        STOFFEL_ADVERTISE_IP=$(pick_ip_on_peer_network "$peer_ip") && break
        echo "Attempt ${attempt}/${max_attempts}: no local address on ${peer_ip%.*}.0/24 yet (have: $(hostname -I)), waiting..."
        sleep 1
        attempt=$((attempt + 1))
    done
    if [ -z "$STOFFEL_ADVERTISE_IP" ]; then
        echo "ERROR: never got an address on the bootstrap's network ${peer_ip%.*}.0/24 (have: $(hostname -I))"
        exit 5
    fi
    echo "Bootstrap ${bootstrap_host} is ${peer_ip}; advertising ${STOFFEL_ADVERTISE_IP} (local addrs: $(hostname -I))"
elif [ -n "${STOFFEL_ADVERTISE_HOST:-}" ]; then
    echo "Resolving STOFFEL_ADVERTISE_HOST=${STOFFEL_ADVERTISE_HOST} via getent hosts..."
    max_attempts=30
    attempt=1
    resolved_ip=""

    while [ $attempt -le $max_attempts ]; do
        resolved_ip=$(getent hosts "${STOFFEL_ADVERTISE_HOST}" 2>/dev/null | awk '{print $1; exit}')
        if [ -n "$resolved_ip" ]; then
            echo "Resolved ${STOFFEL_ADVERTISE_HOST} to ${resolved_ip} (attempt ${attempt}/${max_attempts})"
            STOFFEL_ADVERTISE_IP="$resolved_ip"
            break
        fi
        echo "Attempt ${attempt}/${max_attempts}: ${STOFFEL_ADVERTISE_HOST} not yet resolvable, waiting..."
        sleep 1
        attempt=$((attempt + 1))
    done

    if [ -z "$resolved_ip" ]; then
        echo "ERROR: STOFFEL_ADVERTISE_HOST=${STOFFEL_ADVERTISE_HOST} could not be resolved after ${max_attempts} attempts"
        echo "The DNS name may not be configured correctly on the bridge network."
        exit 5
    fi
elif [ -z "${STOFFEL_ADVERTISE_IP:-}" ]; then
    STOFFEL_ADVERTISE_IP=$(hostname -i | awk '{print $1}')
fi

echo "=========================================="
echo "StoffelVM Node Startup"
echo "=========================================="
echo "Role: ${STOFFEL_ROLE}"
    if [ "${STOFFEL_ROLE}" = "client" ]; then
        echo "Inputs: ${STOFFEL_INPUTS}"
        echo "Client Index: ${STOFFEL_CLIENT_INDEX:-unset}"
        echo "Servers: ${STOFFEL_SERVERS}"
else
    echo "Party ID: ${STOFFEL_PARTY_ID}"
    echo "Bind Address: ${STOFFEL_BIND_ADDR}"
    echo "Bootstrap: ${STOFFEL_BOOTSTRAP_ADDR:-N/A}"
    if [ -n "${STOFFEL_ADVERTISE_HOST:-}" ]; then
        echo "Advertise IP: ${STOFFEL_ADVERTISE_IP} (from STOFFEL_ADVERTISE_HOST=${STOFFEL_ADVERTISE_HOST})"
    else
        echo "Advertise IP: ${STOFFEL_ADVERTISE_IP} (auto-detected)"
    fi
    echo "Expected Clients: ${STOFFEL_EXPECTED_CLIENTS:-none}"
fi
echo "N Parties: ${STOFFEL_N_PARTIES}"
echo "Threshold: ${STOFFEL_THRESHOLD}"
echo "Program: ${STOFFEL_PROGRAM}"
echo "Entry: ${STOFFEL_ENTRY}"
echo "Coordinator: ${STOFFEL_COORD_ADDR:-N/A}"
echo "Preproc Store: ${STOFFEL_PREPROC_STORE:-none}"
echo "Local Store: ${STOFFEL_LOCAL_STORE:-none}"
echo "Profiler: ${STOFFEL_PROFILE:-none}"
echo "Upload Program Bytes: ${STOFFEL_UPLOAD_PROGRAM_BYTES:-true}"
echo "Auth Token: $( [ -n "${STOFFEL_AUTH_TOKEN:-}" ] && echo "configured" || echo "not set" )"
echo "=========================================="

# Wait for a host:port to be available (UDP check for QUIC)
wait_for_host() {
    local host=$1
    local port=$2
    local max_attempts=${3:-60}
    local attempt=1

    echo "Waiting for ${host}:${port} to be available (QUIC/UDP)..."

    # QUIC is UDP and ping/raw sockets are unavailable under gVisor (runsc),
    # so the only portable readiness signal is DNS: the peer's name resolves
    # once its container is attached to the shared network. The application
    # has its own connection retry logic beyond that.
    while [ $attempt -le $max_attempts ]; do
        if getent hosts "$host" >/dev/null 2>&1; then
            echo "${host} resolves; proceeding (app handles QUIC retries)"
            return 0
        fi
        echo "Attempt ${attempt}/${max_attempts}: ${host} not resolvable yet, waiting..."
        sleep 2
        attempt=$((attempt + 1))
    done

    echo "ERROR: ${host}:${port} did not become available after ${max_attempts} attempts"
    return 1
}

resolve_socket_addr() {
    local addr=$1
    local host
    local port
    local resolved

    host=$(echo "$addr" | cut -d: -f1)
    port=$(echo "$addr" | cut -d: -f2)

    resolved=$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}')
    if [ -z "$resolved" ]; then
        resolved=$(ping -c 1 "$host" 2>/dev/null | sed -n 's/^PING [^(]*(\([^)]*\)).*/\1/p' | head -n 1)
    fi

    if [ -z "$resolved" ]; then
        echo "$addr"
    else
        echo "${resolved}:${port}"
    fi
}

# Build command based on role
build_command() {
    local cmd="/app/stoffel-run"

    if [ "${STOFFEL_ROLE}" = "client" ]; then
        # Client mode: connect to coordinator and submit inputs
        cmd="${cmd} --client"
        cmd="${cmd} --inputs ${STOFFEL_INPUTS}"
        cmd="${cmd} --servers ${STOFFEL_SERVERS}"
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
        cmd="${cmd} --threshold ${STOFFEL_THRESHOLD:-1}"
        if [ -n "${STOFFEL_OUTPUTS:-}" ]; then
            cmd="${cmd} --outputs ${STOFFEL_OUTPUTS}"
        fi
        if [ -n "${STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS:-}" ]; then
            cmd="${cmd} --output-fixed-point-fractional-bits ${STOFFEL_OUTPUT_FIXED_POINT_FRACTIONAL_BITS}"
        fi
        if [ -n "${STOFFEL_COORD_ADDR:-}" ]; then
            cmd="${cmd} --off-chain-coord ${STOFFEL_COORD_ADDR}"
            cmd="${cmd} --cert ${STOFFEL_CERT}"
            cmd="${cmd} --key ${STOFFEL_KEY}"
            cmd="${cmd} --timestamp ${STOFFEL_TIMESTAMP:-0}"
        fi
        if [ -n "${STOFFEL_CLIENT_INDEX:-}" ]; then
            cmd="${cmd} --client-index ${STOFFEL_CLIENT_INDEX}"
        fi
        if [ -n "${STOFFEL_MPC_BACKEND:-}" ]; then
            cmd="${cmd} --mpc-backend ${STOFFEL_MPC_BACKEND}"
        fi
        if [ -n "${STOFFEL_MPC_CURVE:-}" ]; then
            cmd="${cmd} --mpc-curve ${STOFFEL_MPC_CURVE}"
        fi
        echo "$cmd"
        return
    fi

    # Add program path and entry function for non-client modes
    cmd="${cmd} ${STOFFEL_PROGRAM} ${STOFFEL_ENTRY}"

    if [ "${STOFFEL_UPLOAD_PROGRAM_BYTES:-true}" = "false" ]; then
        cmd="${cmd} --no-program-upload"
    fi

    if [ "${STOFFEL_ROLE}" = "leader" ]; then
        # Leader mode: runs bootnode + party 0
        cmd="${cmd} --leader"
        cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
        cmd="${cmd} --threshold ${STOFFEL_THRESHOLD}"
        BIND_PORT=$(echo "${STOFFEL_BIND_ADDR}" | awk -F: '{print $NF}')
        ADVERTISE_PORT=$((BIND_PORT + 1000))
        cmd="${cmd} --advertise ${STOFFEL_ADVERTISE_IP}:${ADVERTISE_PORT}"
    elif [ "${STOFFEL_ROLE}" = "bootnode" ]; then
        # Bootnode-only mode (no program execution)
        cmd="/app/stoffel-run --bootnode"
        cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
    else
        # Regular party mode
        RESOLVED_BOOTSTRAP_ADDR=$(resolve_socket_addr "${STOFFEL_BOOTSTRAP_ADDR}")
        cmd="${cmd} --party-id ${STOFFEL_PARTY_ID}"
        cmd="${cmd} --bootstrap ${RESOLVED_BOOTSTRAP_ADDR}"
        cmd="${cmd} --bind ${STOFFEL_BIND_ADDR}"
        cmd="${cmd} --n-parties ${STOFFEL_N_PARTIES}"
        cmd="${cmd} --threshold ${STOFFEL_THRESHOLD}"
        BIND_PORT=$(echo "${STOFFEL_BIND_ADDR}" | awk -F: '{print $NF}')
        cmd="${cmd} --advertise ${STOFFEL_ADVERTISE_IP}:${BIND_PORT}"
    fi

    # Coordinator flags (for leader, party, and bootnode modes)
    if [ -n "${STOFFEL_COORD_ADDR:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --off-chain-coord ${STOFFEL_COORD_ADDR}"
        cmd="${cmd} --cert ${STOFFEL_CERT}"
        cmd="${cmd} --key ${STOFFEL_KEY}"
        cmd="${cmd} --timestamp ${STOFFEL_TIMESTAMP:-0}"
    fi

    if [ -n "${STOFFEL_RPC_ADDR:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --rpc-bind ${STOFFEL_RPC_ADDR}"
    fi

    if [ -n "${STOFFEL_EXPECTED_CLIENTS:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --expected-clients ${STOFFEL_EXPECTED_CLIENTS}"
    fi

    if [ -n "${STOFFEL_WAIT_FOR_CLIENTS:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --wait-for-clients ${STOFFEL_WAIT_FOR_CLIENTS}"
    fi

    if [ -n "${STOFFEL_CLIENT_INPUT_COUNT:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --client-input-count ${STOFFEL_CLIENT_INPUT_COUNT}"
    fi

    if [ -n "${STOFFEL_PREPROC_STORE:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --preproc-store ${STOFFEL_PREPROC_STORE}"
    fi

    if [ -n "${STOFFEL_LOCAL_STORE:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --local-store ${STOFFEL_LOCAL_STORE}"
    fi

    if [ -z "${STOFFEL_COORD_ADDR:-}" ] && [ -n "${STOFFEL_CERT:-}" ] && [ -n "${STOFFEL_KEY:-}" ] && [ "${STOFFEL_ROLE}" != "bootnode" ]; then
        cmd="${cmd} --cert ${STOFFEL_CERT}"
        cmd="${cmd} --key ${STOFFEL_KEY}"
    fi

    # Add MPC backend if specified
    if [ -n "${STOFFEL_MPC_BACKEND:-}" ]; then
        cmd="${cmd} --mpc-backend ${STOFFEL_MPC_BACKEND}"
    fi

    # Add MPC curve if specified
    if [ -n "${STOFFEL_MPC_CURVE:-}" ]; then
        cmd="${cmd} --mpc-curve ${STOFFEL_MPC_CURVE}"
    fi

    # Add optional trace flags
    if [ "${STOFFEL_TRACE_INSTR}" = "true" ]; then
        cmd="${cmd} --trace-instr"
    fi
    if [ "${STOFFEL_TRACE_REGS}" = "true" ]; then
        cmd="${cmd} --trace-regs"
    fi
    if [ "${STOFFEL_TRACE_STACK}" = "true" ]; then
        cmd="${cmd} --trace-stack"
    fi

    # Add NAT traversal flags if enabled
    if [ "${STOFFEL_ENABLE_NAT}" = "true" ]; then
        cmd="${cmd} --nat"
        if [ -n "${STOFFEL_STUN_SERVERS}" ]; then
            cmd="${cmd} --stun-servers ${STOFFEL_STUN_SERVERS}"
        fi
    fi

    echo "$cmd"
}

run_command() {
    local cmd="$1"
    local profile="${STOFFEL_PROFILE:-}"
    local profile_party="${STOFFEL_PROFILE_PARTY_ID:-0}"
    local party_id="${STOFFEL_PARTY_ID:-client}"
    local out_dir="${STOFFEL_PROFILE_DIR:-/app/profiles}"
    local label="${STOFFEL_PROFILE_LABEL:-party${party_id}}"

    if [ -z "$profile" ] || [ "$profile" = "none" ] || [ "$party_id" != "$profile_party" ]; then
        exec $cmd
    fi

    mkdir -p "$out_dir"
    echo "Profiling party ${party_id} with ${profile}; output dir: ${out_dir}"

    case "$profile" in
        heaptrack)
            exec heaptrack -o "${out_dir}/${label}.heaptrack" $cmd
            ;;
        massif)
            exec valgrind \
                --tool=massif \
                --pages-as-heap=yes \
                --massif-out-file="${out_dir}/${label}.massif" \
                $cmd
            ;;
        perf)
            exec perf record \
                -F "${STOFFEL_PERF_FREQUENCY:-99}" \
                -g \
                -o "${out_dir}/${label}.perf.data" \
                -- $cmd
            ;;
        *)
            echo "ERROR: unknown STOFFEL_PROFILE '${profile}' (expected heaptrack, massif, perf, or none)" >&2
            exit 2
            ;;
    esac
}

# Main execution logic
main() {
    # Handle client mode
    if [ "${STOFFEL_ROLE}" = "client" ]; then
        # Wait for servers to be ready
        # Parse the first server address to check connectivity
        FIRST_SERVER=$(echo "${STOFFEL_SERVERS}" | cut -d',' -f1)
        SERVER_HOST=$(echo "${FIRST_SERVER}" | cut -d: -f1)
        SERVER_PORT=$(echo "${FIRST_SERVER}" | cut -d: -f2)

        # Add startup delay to let servers complete preprocessing
        DELAY=${STOFFEL_CLIENT_DELAY:-30}
        echo "Client: waiting ${DELAY}s for servers to complete preprocessing..."
        sleep $DELAY

        # Wait for first server to be reachable
        if ! wait_for_host "$SERVER_HOST" "$SERVER_PORT" 120; then
            echo "Failed to connect to server at ${FIRST_SERVER}"
            exit 1
        fi

        # Build and execute the command
        CMD=$(build_command)
        echo ""
        echo "Executing: ${CMD}"
        echo "=========================================="
        echo ""

        run_command "$CMD"
    fi

    # If we're a party (not leader), wait for the bootnode to be ready
    if [ "${STOFFEL_ROLE}" = "party" ] && [ -n "${STOFFEL_BOOTSTRAP_ADDR}" ] && [ "${STOFFEL_SKIP_HOST_WAIT:-false}" != "true" ]; then
        # Parse host and port from bootstrap address
        BOOTSTRAP_HOST=$(echo "${STOFFEL_BOOTSTRAP_ADDR}" | cut -d: -f1)
        BOOTSTRAP_PORT=$(echo "${STOFFEL_BOOTSTRAP_ADDR}" | cut -d: -f2)

        # Small fixed delay to let bootnode stabilize
        echo "Party ${STOFFEL_PARTY_ID}: waiting 2s before connecting..."
        sleep 2

        # Wait for bootnode to be available
        if ! wait_for_host "$BOOTSTRAP_HOST" "$BOOTSTRAP_PORT" 120; then
            echo "Failed to connect to bootnode at ${STOFFEL_BOOTSTRAP_ADDR}"
            exit 1
        fi
    fi

    # Build and execute the command
    CMD=$(build_command)
    echo ""
    echo "Executing: ${CMD}"
    echo "=========================================="
    echo ""

    run_command "$CMD"
}

main "$@"
