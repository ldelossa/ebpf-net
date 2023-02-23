#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2
#define TC_ACT_REDIRECT		7

#define AF_INET		        2	/* Internet IP Protocol 	*/

struct bpf_fib_lookup fib_params = {0};

int fib_lookup_ret = 0;

SEC("tc")
int fib_lookup(struct __sk_buff *skb)
{
        bpf_printk("performing FIB lookup\n");

        bpf_printk("fib lookup original ret: %d\n", fib_lookup_ret);

	fib_lookup_ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params),
					0);

        bpf_printk("fib lookup ret: %d\n", fib_lookup_ret);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";