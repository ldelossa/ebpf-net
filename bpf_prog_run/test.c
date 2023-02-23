#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <bpf/bpf_endian.h>
#include "fib_lookup.skel.h"
#include "net/ethernet.h"
#include "linux/ip.h"
#include "netinet/tcp.h"

#define TARGET_IFINDEX 2

// in our test, we only care that the packet is the correct size,
// since our test does not touch any packet data.
char v4_pkt[(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))];

// we'll hardcore the ifindex here, since w can be pretty certain that ifindex 1
// is the loopback address.
struct __sk_buff skb = {
        .ifindex = 1 // mock that the skb came from loopback.
};

int main (int argc, char *argv[]) {
        struct fib_lookup_bpf *skel;
        int prog_fd, err = 0;

        // define our BPF_PROG_RUN options with our mock data.
        struct bpf_test_run_opts opts = {
                // required, or else bpf_prog_test_run_opts will fail
                .sz = sizeof(struct bpf_test_run_opts),
                // data_in will wind up being ctx.data
                .data_in = &v4_pkt,
                .data_size_in = sizeof(v4_pkt),
                // ctx is an skb in this case
                .ctx_in = &skb,
                .ctx_size_in = sizeof(skb)
        };

        // load our fib lookup test program into the kernel and return our
        // skeleton handle to it.
        skel = fib_lookup_bpf__open_and_load();
        if (!skel) {
                printf("[error]: failed to open and load skeleton: %d\n", err);
                return -1;
        }

        // inject our test parameters into the fib lookup parameter, this primes
        // our test.
        skel->bss->fib_lookup_ret = -1;
        skel->bss->fib_params.family = AF_INET;
        skel->bss->fib_params.ipv4_src = 0x100007f;
        skel->bss->fib_params.ipv4_dst = 0x8080808;
        skel->bss->fib_params.ifindex = 1;

        // get the prog_fd from the skeleton, and run our test.
        prog_fd = bpf_program__fd(skel->progs.fib_lookup);
        err = bpf_prog_test_run_opts(prog_fd, &opts);
        if (err != 0) {
                printf("[error]: bpf test run failed: %d\n", err);
                return -2;
        }

        // check global variables for response
        if (skel->bss->fib_lookup_ret != 0) {
                printf("[FAIL]: fib lookup returned: %d", skel->bss->fib_lookup_ret);
                return -1;
        }

        if (skel->bss->fib_params.ifindex != TARGET_IFINDEX) {
                printf("[FAIL]: fib lookup did not choose default gw interface: %d", skel->bss->fib_params.ifindex);
                return -1;
        }

        printf("[PASS]: ifindex %d\n", skel->bss->fib_params.ifindex);
        return 0;
}