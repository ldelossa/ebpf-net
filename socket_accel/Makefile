socket_accel_bpf.o: socket_accel_bpf.c
	clang -target bpf -Wall -O2 -g -c socket_accel_bpf.c -o $@

.PHONY:
attach:
	sudo tc qdisc replace dev eth0 clsact
	sudo tc filter replace dev eth0 ingress bpf object-file socket_accel_bpf.o section tc