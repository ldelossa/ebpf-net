MAKEFLAGS += --no-print-directory 
IP = sudo ip
NETNS = $(IP) netns
EXEC = $(NETNS) exec
NET_1 = "netns_1"
NET_2 = "netns_2"

up: packet_redirect.bpf.o vmlinux.h
	# Purging old environment...
	-make down
	# Creating network namespaces...
	$(NETNS) add $(NET_1)
	$(NETNS) add $(NET_2)
	# Configuring the following topology...
	# |host_ns              |netns_1              |netns_2                |
	# |veth1@1 10.0.1.10|---|veth1@2 10.0.1.11    |                       |
	# |                     |veth2@1 10.0.2.10|---|veth2@2 10.0.2.11      |
	# |                     |                     |server  10.0.2.11:8000 |
	$(IP) link add name veth1@1 type veth peer name veth1@2 netns $(NET_1)
	$(IP) addr add 10.0.1.10/24 dev veth1@1
	$(EXEC) $(NET_1) ip addr add 10.0.1.11/24 dev veth1@2
	$(EXEC) $(NET_1) ip link add name veth2@1 type veth peer name veth2@2 netns $(NET_2)
	$(EXEC) $(NET_1) ip addr add 10.0.2.10/24 dev veth2@1
	$(EXEC) $(NET_2) ip addr add 10.0.2.11/24 dev veth2@2
	$(IP) link set veth1@1 up
	$(EXEC) $(NET_1) ip link set veth1@2 up
	$(EXEC) $(NET_1) ip link set veth2@1 up
	$(EXEC) $(NET_2) ip link set veth2@2 up
	$(IP) route add 10.0.2.0/24 dev veth1@1
	$(EXEC) $(NET_2) ip route add 10.0.1.0/24 dev veth2@2
	# veth1@2 in netns_1 must proxy ARP requests for host_ns and netns_2 so
	# host_ns can resolve MAC addresses for netns_2 and vice versa.
	$(EXEC) $(NET_1) /bin/sh -c 'echo 1 > /proc/sys/net/ipv4/conf/veth1@2/proxy_arp'
	# Hardcode veth2@2 to a dummy MAC for sake of demonstration purposes.
	$(EXEC) $(NET_2) ip link set dev veth2@2 addr 02:00:00:00:00:00
	# Attaching eBPF program...
	$(EXEC) $(NET_1) tc qdisc replace dev veth1@2 clsact
	$(EXEC) $(NET_1) tc filter replace dev veth1@2 ingress bpf direct-action object-file $< section tc
	# LISTENING FOR UDP PACKET @ 10.0.2.11 7777...
	# Use 'make listen' to listen for another packet...
	@make listen

.PHONY:
down:
	$(NETNS) del $(NET_1)
	$(NETNS) del $(NET_2)

.PHONY:
listen:
	$(EXEC) $(NET_2) nc -u -l 10.0.2.11 7777

packet_redirect.bpf.o:

%.bpf.o: %.bpf.c vmlinux.h 
	# Compiling eBPF program...
	clang -O2 -target bpf -g3 -c $< -o $@

vmlinux.h: 
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 
