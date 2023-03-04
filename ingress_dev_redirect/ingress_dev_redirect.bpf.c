#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// from linux/if_ether.h
#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define ETH_TLEN	2		/* Octets in ethernet type field */
#define ETH_HLEN	14		/* Total octets in header.	 */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload	 */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS		 */

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2
#define TC_ACT_REDIRECT		7

#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/

#define IPV4_IHL_BYTES(ip4) \
        ((ip4->ihl * 32) / 8)

#define IPPROTO_UDP 17
#define IPPROTO_TCP 6

struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, 65535);
        __type(key, struct bpf_sock_tuple);
        __type(value, __u64);
	      __uint(pinning, LIBBPF_PIN_BY_NAME);
} accepted_sockets SEC(".maps");

static __always_inline int tuple_extract_tcp(void *data, void *data_end, uint64_t l4_off, struct bpf_sock_tuple *tuple) {
        if ((data + sizeof(struct ethhdr) + l4_off + sizeof(struct tcphdr)) > data_end)
                return -3;

        struct {
                uint16_t sport;
                uint16_t dport;
        } *tcphdr = (void *)(data + ETH_HLEN + l4_off);

        tuple->ipv4.sport = tcphdr->sport;
        tuple->ipv4.dport = tcphdr->dport;

        return 1;
}

static __always_inline int tuple_extract_udp(void *data, void *data_end, uint64_t l4_off, struct bpf_sock_tuple *tuple) {

}

static __always_inline int tuple_extract_ip4(void *data, void *data_end, struct bpf_sock_tuple *tuple) {
        if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
                return -2;
        struct iphdr *ip4 = data + sizeof(struct ethhdr);

        uint64_t l4_off = ETH_HLEN + IPV4_IHL_BYTES(ip4);

        tuple->ipv4.saddr = ip4->saddr;
        tuple->ipv4.daddr = ip4->daddr;

        switch (ip4->protocol) {
                case IPPROTO_TCP:
                        bpf_printk("extracting tcp from skb\n");
                        return tuple_extract_tcp(data, data_end, l4_off, tuple);
                case IPPROTO_UDP:
                        bpf_printk("extracting udp from skb\n");
                        return tuple_extract_udp(data, data_end, l4_off, tuple);
                default:
                        bpf_printk("not handling ip protocol: %d\n", bpf_ntohs(ip4->protocol));
                        return -2;
        }
}

static __always_inline int tuple_extract_ip6(void *data, void *data_end, struct bpf_sock_tuple *tuple) {

}

static __always_inline int tuple_extract_skb(struct __sk_buff *skb, struct bpf_sock_tuple *tuple)
{
        void *data_end = (void *)(uint64_t)(skb->data_end);
        void *data = (void *)(uint64_t)(skb->data);
        if ((data + sizeof(struct ethhdr)) > data_end)
                return -1;
        struct ethhdr *eth = data;
        switch (bpf_ntohs(eth->h_proto)) {
                case ETH_P_IP:
                        bpf_printk("extracting ipv4 from skb\n");
                        return tuple_extract_ip4(data, data_end, tuple);
                case ETH_P_IPV6:
                        bpf_printk("extracting ipv6 from skb\n");
                        return tuple_extract_ip6(data, data_end, tuple);
                default:
                        bpf_printk("not handling eth protocol: %d\n", bpf_ntohs(eth->h_proto));
                        return -1;
        }
}

SEC("tc")
int tc_ingress_socket_redirect(struct __sk_buff *skb) {
        struct bpf_fib_lookup rt = {0};
        bpf_printk("performing skb redirect\n");

        bpf_skb_pull_data(skb, 0);

        struct bpf_sock_tuple tuple = {0};

        int ret = tuple_extract_skb(skb, &tuple);
        if (ret != 1) {
                return TC_ACT_OK;
        }

        bpf_printk("performing bpf_redirect\n");
        if (bpf_redirect(3, 0) != TC_ACT_REDIRECT) {
                bpf_printk("bpf_redirect failed %d\n");
                return TC_ACT_SHOT;
        }
        return TC_ACT_REDIRECT;

        // // do a fib lookup on the destination
        // rt.family = AF_INET;
        // rt.ifindex = skb->ifindex;
        // ret = bpf_fib_lookup(skb, &rt, sizeof(rt), 0);
        // bpf_printk("fib lookup returns: %d\n", ret);

        // return TC_ACT_SHOT;
};

char _license[] SEC("license") = "GPL";
