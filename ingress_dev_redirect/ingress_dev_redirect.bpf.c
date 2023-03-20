#include "../vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


// from linux/if_ether.h
#define ETH_ALEN 6         /* Octets in one ethernet addr	 */
#define ETH_TLEN 2         /* Octets in ethernet type field */
#define ETH_HLEN 14        /* Total octets in header.	 */
#define ETH_ZLEN 60        /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN 1500  /* Max. octets in payload	 */
#define ETH_FRAME_LEN 1514 /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN 4      /* Octets in the FCS		 */

#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7

#define AF_INET 2   /* Internet IP Protocol 	*/
#define AF_INET6 10 /* IP version 6			*/

#define IPV4_IHL_BYTES(ip4) ((ip4->ihl * 32) / 8)

#define IPPROTO_UDP 17
#define IPPROTO_TCP 6

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} accepted_sockets SEC(".maps");

static __always_inline int tuple_extract_tcp(void *data, void *data_end,
                                             uint64_t l4_off,
                                             struct bpf_sock_tuple *tuple) {
    if ((data + sizeof(struct ethhdr) + l4_off + sizeof(struct tcphdr)) >
        data_end)
        return -4;

    struct {
        uint16_t sport;
        uint16_t dport;
    } *tcphdr = (void *)(data + ETH_HLEN + l4_off);

    tuple->ipv4.sport = tcphdr->sport;
    tuple->ipv4.dport = tcphdr->dport;

    return 0;
}

static __always_inline int tuple_extract_udp(void *data, void *data_end,
                                             uint64_t l4_off,
                                             struct bpf_sock_tuple *tuple) {}

static __always_inline int tuple_extract_ip4(void *data, void *data_end,
                                             struct bpf_sock_tuple *tuple) {
    if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
        return -3;
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
            bpf_printk("not handling ip protocol: %d\n",
                       bpf_ntohs(ip4->protocol));
            return -3;
    }
}

static __always_inline int tuple_extract_ip6(void *data, void *data_end,
                                             struct bpf_sock_tuple *tuple) {}

// extracts layer2/3/4 info into from skb into bpf_sock_tuple.
// on success, the layer 3 protocol is returned, on failure
// a negative value is returned indicating which network layer
// failed to be parsed.
static __always_inline int tuple_extract_skb(struct __sk_buff *skb,
                                             struct bpf_sock_tuple *tuple) {
    void *data_end = (void *)(uint64_t)(skb->data_end);
    void *data = (void *)(uint64_t)(skb->data);
    if ((data + sizeof(struct ethhdr)) > data_end) return -2;

    struct ethhdr *eth = data;
    switch (bpf_ntohs(eth->h_proto)) {
        case ETH_P_IP:
            bpf_printk("extracting ipv4 from skb\n");
            return tuple_extract_ip4(data, data_end, tuple) ?: ETH_P_IP;
        case ETH_P_IPV6:
            bpf_printk("extracting ipv6 from skb\n");
            return tuple_extract_ip6(data, data_end, tuple) ?: ETH_P_IPV6;
        default:
            bpf_printk("not handling eth protocol: %d\n",
                       bpf_ntohs(eth->h_proto));
            return -2;
    }
}

SEC("tc")
int tc_ingress_socket_redirect(struct __sk_buff *skb) {
    struct bpf_fib_lookup rt = {0};
    struct bpf_sock_tuple tuple = {0};
    struct bpf_sock_tuple lookup_tuple = {0};

    bpf_printk("performing skb redirect\n");

    if (bpf_skb_pull_data(skb, 0) < 0) {
        bpf_printk("could not pull skb\n");
        return TC_ACT_OK;
    }

    int ret = tuple_extract_skb(skb, &tuple);
    if (ret < 0) {
        bpf_printk("failed to parse skb in network layer %d", ret * -1);
        return TC_ACT_OK;
    }

    switch (ret) {
        case ETH_P_IP:
            lookup_tuple.ipv4.saddr = tuple.ipv4.saddr;
            lookup_tuple.ipv4.daddr = tuple.ipv4.daddr;
        case ETH_P_IPV6:
            lookup_tuple.ipv6.saddr[0] = tuple.ipv6.saddr[0];
            lookup_tuple.ipv6.saddr[1] = tuple.ipv6.saddr[1];
            lookup_tuple.ipv6.saddr[2] = tuple.ipv6.saddr[2];
            lookup_tuple.ipv6.saddr[3] = tuple.ipv6.saddr[3];

            lookup_tuple.ipv6.daddr[0] = tuple.ipv6.daddr[0];
            lookup_tuple.ipv6.daddr[1] = tuple.ipv6.daddr[1];
            lookup_tuple.ipv6.daddr[2] = tuple.ipv6.daddr[2];
            lookup_tuple.ipv6.daddr[3] = tuple.ipv6.daddr[3];
    }

    // check for cached device id.


    // perform a fib lookup, if successful, cache the destination intf
    // in the dev map with the tuple key for later usage.
    rt.family = AF_INET;
    rt.ifindex = skb->ifindex;
    rt.ipv4_src = tuple.ipv4.saddr;
    rt.ipv4_dst = tuple.ipv4.daddr;
    ret = bpf_fib_lookup(skb, &rt, sizeof(rt), 0);
    bpf_printk("fib lookup returns: %d\n", ret);

    // return TC_ACT_SHOT;
};

char _license[] SEC("license") = "GPL";
