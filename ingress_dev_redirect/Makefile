ingress_dev_redirect.bpf.o: ingress_dev_redirect.bpf.c
	clang -target bpf -Wall -O2 -g -c $< -o $@

.PHONY: attach toplogy topology-down

attach:
	sudo ip netns exec netns-2 tc qdisc replace dev veth1@2 clsact
	sudo ip netns exec netns-2 tc filter replace dev veth1@2 ingress prio 1 handle 1 bpf da object-file ingress_dev_redirect.bpf.o section tc

topology-down:
	-sudo ip netns delete netns-2
	-sudo ip netns delete netns-3

topology:
	make topology-down

	# make network namespaces, we are already in netns-1 ("host" netns).
	sudo ip netns add netns-2
	sudo ip netns add netns-3

	# wire up netns-1 to netns-2
	sudo ip link add veth1@1 type veth peer name veth1@2 netns netns-2

	sudo ip link set dev veth1@1 up
	sudo ip netns exec netns-2 ip link set dev veth1@2 up

	sudo ip addr add dev veth1@1 10.10.2.10/24
	sudo ip netns exec netns-2 ip addr add dev veth1@2 10.10.2.11/24

	# wire up netns-2 to netns-3
	sudo ip netns exec netns-2 ip link add veth2@1 type veth peer name veth2@2 netns netns-3

	sudo ip netns exec netns-2 ip link set dev veth2@1 up
	sudo ip netns exec netns-3 ip link set dev veth2@2 up

	sudo ip netns exec netns-2 ip addr add dev veth2@1 10.10.3.10/24
	sudo ip netns exec netns-3 ip addr add dev veth2@2 10.10.3.11/24
	sudo ip netns exec netns-3 ip addr add dev veth2@2 10.10.3.20/24

	# setup routing table
	sudo ip route add 10.10.0.0/16 via 10.10.2.11