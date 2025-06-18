#!/bin/bash

set -ex
set -u

readonly TMUX=ipv6

# Kill tmux previous session
tmux kill-session -t "${TMUX}" 2>/dev/null || true

# Clean up previous network namespaces
ip -all netns delete

ip netns add h0
ip netns add h1
ip netns add r0


ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3

ip link set veth0 netns h0
ip link set veth1 netns r0
ip link set veth2 netns r0
ip link set veth3 netns h1

###################
#### Node: h0 #####
###################
echo -e "\nNode: h0"
ip netns exec h0 ip link set dev lo up
ip netns exec h0 ip link set dev veth0 up
ip netns exec h0 ip addr add 10.0.0.1/24 dev veth0
ip netns exec h0 ip addr add cafe::1/64 dev veth0

ip netns exec h0 ip -6 route add default via cafe::254 dev veth0
ip netns exec h0 ip -4 route add default via 10.0.0.254 dev veth0

###################
#### Node: r0 #####
###################
echo -e "\nNode: r0"

ip netns exec r0 sysctl -w net.ipv4.ip_forward=1
ip netns exec r0 sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec r0 sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec r0 sysctl -w net.ipv4.conf.veth1.rp_filter=0
ip netns exec r0 sysctl -w net.ipv4.conf.veth2.rp_filter=0

ip netns exec r0 ip link set dev lo up
ip netns exec r0 ip link set dev veth1 up
ip netns exec r0 ip link set dev veth2 up

ip netns exec r0 ip addr add cafe::254/64 dev veth1
ip netns exec r0 ip addr add 10.0.0.254/24 dev veth1

ip netns exec r0 ip addr add beef::254/64 dev veth2
ip netns exec r0 ip addr add 10.0.2.254/24 dev veth2

set +e
read -r -d '' r0_env <<-EOF
	# Set up a private BPF filesystem for this bash process.
	# This mounts the BPF filesystem at /sys/fs/bpf.
	# Note:
	# - Child processes of this bash will have access to this instance of
	#   the BPF filesystem.
	# - If you need to access the same BPF filesystem (e.g., to interact
	#   with BPF maps) from outside this process, use 'nsenter' with the '-m'
	#   (mount namespace) and '-t' (target process ID) options, pointing to
	#   the parent process's PID that launched this bash.
	#
	mount -t bpf bpf /sys/fs/bpf/
	mkdir -p /sys/fs/bpf/netprog/{progs,maps}

	mount -t tracefs nodev /sys/kernel/tracing

        # It allows to load maps with many entries without failing
        ulimit -l unlimited

	# The command bpftool prog loadall netprog.bpf.o /sys/fs/bpf/netprog
	# loads a BPF program from the object file netprog.bpf.o into the
	# kernel and attaches it with the identifier or link name netprog,
	# storing it in the specified BPF filesystem directory /sys/fs/bpf/.
	bpftool prog \
		loadall netprog.bpf.o /sys/fs/bpf/netprog/progs \
		pinmaps /sys/fs/bpf/netprog/maps

	# The command attaches an eBPF program pinned at
	# /sys/fs/bpf/netprog/xdp_prog_protocol_classifier to the veth1 network
	# interface using bpftool net attach xdp.
	bpftool net attach xdp \
		pinned /sys/fs/bpf/netprog/progs/xdp_prog_protocol_classifier dev veth1

        /bin/bash
EOF
set -e

###################
#### Node: h1 #####
###################
echo -e "\nNode: h1"
ip netns exec h1 ip link set dev lo up
ip netns exec h1 ip link set dev veth3 up
ip netns exec h1 ip addr add 10.0.2.1/24 dev veth3
ip netns exec h1 ip addr add beef::1/64 dev veth3

ip netns exec h1 ip -4 route add default via 10.0.2.254 dev veth3
ip netns exec h1 ip -6 route add default via beef::254 dev veth3

## Create a new tmux session
tmux new-session -d -s "${TMUX}" -n h0 ip netns exec h0 bash
tmux new-window -t "${TMUX}" -n r0 ip netns exec r0 bash -c "${r0_env}"
tmux new-window -t "${TMUX}" -n h1 ip netns exec h1 bash
tmux select-window -t :0
tmux set-option -g mouse on
tmux attach -t "${TMUX}"
