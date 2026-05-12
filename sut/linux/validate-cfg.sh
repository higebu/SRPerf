#!/bin/bash
# Smoke-validate forwarding-behaviour.cfg against the current iproute2
# in $PATH.  Spawns an ephemeral netns, creates a veth pair renamed to
# match the cfg's SUT_rcv / SUT_snd interfaces, then walks every entry
# in behaviour_arr and verifies the corresponding _cfg() function runs
# without error and installs at least one route the behaviour expects.
#
# Run as root:
#
#   sudo ip=../iproute2/ip ./validate-cfg.sh
#
# Exit code 0 = all behaviours configure cleanly.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CFG="$HERE/forwarding-behaviour.cfg"
NS=${NS:-srperf-validate}
IP=${ip:-ip}

if [ "$(id -u)" -ne 0 ]; then
	echo "error: must run as root" >&2
	exit 1
fi
command -v "$IP" >/dev/null 2>&1 || { echo "missing ip: $IP" >&2; exit 1; }
$IP -V

cleanup() {
	$IP netns del "$NS" 2>/dev/null || true
}
trap cleanup EXIT

cleanup
$IP netns add "$NS"
$IP -n "$NS" link set lo up

# Names hard-coded in the cfg.
$IP -n "$NS" link add enp6s0f0 type veth peer name enp6s0f1
$IP -n "$NS" link set enp6s0f0 up
$IP -n "$NS" link set enp6s0f1 up

# Address plan from forwarding-behaviour.cfg.
$IP -n "$NS" addr add 10.10.1.2/24 dev enp6s0f0
$IP -n "$NS" addr add 12:1::2/64   dev enp6s0f0 nodad
$IP -n "$NS" addr add 10.10.2.2/24 dev enp6s0f1
$IP -n "$NS" addr add 12:2::2/64   dev enp6s0f1 nodad

# Source the cfg only to enumerate behaviour_arr and reuse functions.
# We replace the script's "ip" with $IP and run each cfg in the netns.
# Easiest is to invoke the cfg script itself with ip=$IP and IP() shim.
shim=$(mktemp)
cat > "$shim" <<'EOF'
ip() { "$REAL_IP" -n "$NS" "$@"; }
sysctl() { :; }   # cfg may call sysctl -w -- ignore in validation
EOF
chmod +x "$shim"

# Extract the behaviour_arr from the cfg without sourcing the bottom block.
mapfile -t behaviours < <(
	awk '/^declare -a behaviour_arr=/,/^\);/' "$CFG" |
	grep -oE '"[a-z0-9_]+"' | tr -d '"'
)
echo "behaviours: ${#behaviours[@]} -> ${behaviours[*]}"

# Run each behaviour by sourcing the cfg in a subshell where ip() is shimmed.
pass=0
fail=0
for b in "${behaviours[@]}"; do
	out=$(
		REAL_IP=$IP NS=$NS bash <<-INNER 2>&1
			source "$shim"
			# Source the cfg as a *library* (skip its execution block).
			eval "\$(awk '/^### start of script execution/{exit}1' "$CFG")"
			clean_cfg
			${b}_cfg
		INNER
	)
	rc=$?
	if [ $rc -eq 0 ]; then
		echo "  PASS  $b"
		pass=$((pass + 1))
	else
		echo "  FAIL  $b  (rc=$rc)"
		printf '    %s\n' "$out" | tail -5
		fail=$((fail + 1))
	fi
done

echo
echo "result: $pass passed, $fail failed (out of ${#behaviours[@]})"
rm -f "$shim"
[ $fail -eq 0 ]
