#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

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

#define IPV4_IHL_BYTES(ip4) \
        ((ip4->ihl * 32) / 8)

#define IPPROTO_UDP 17
#define IPPROTO_TCP 6

struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, 65535);
        __type(key, struct bpf_sock_tuple);
        __type(value, __u64);
} accepted_sockets SEC(".maps");

static __always_inline int skb_extract_tcp(struct __sk_buff *skb, uint64_t l4_off, struct bpf_sock_tuple *tuple) {
        if ((skb->data + ETH_HLEN + l4_off) > skb->data_end)
                return -1;

        struct {
                uint16_t sport;
                uint16_t dport;
        } *tcphdr = (void *)(skb->data + ETH_HLEN + l4_off);

        tuple->ipv4.sport = tcphdr->sport;
        tuple->ipv4.dport = tcphdr->dport;

        return 1;
}

static __always_inline int skb_extract_udp(struct __sk_buff *skb, uint32_t l4_off, struct bpf_sock_tuple *tuple) {

}

static __always_inline int skb_extract_ip4(void *data, void *data_end, struct bpf_sock_tuple *tuple) {
        if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
                return -1;
        struct iphdr *ip4 = data + sizeof(struct ethhdr);

        uint64_t l4_off = ETH_HLEN + IPV4_IHL_BYTES(ip4);

        tuple->ipv4.saddr = ip4->saddr;
        tuple->ipv4.daddr = ip4->daddr;

        switch (ip4->protocol) {
                case IPPROTO_TCP:
                        // return skb_extract_tcp(skb, l4_off, tuple);
                case IPPROTO_UDP:
                        // return skb_extract_udp(skb, l4_off, tuple);
                default:
                        return -1;
        }
}

static __always_inline int skb_extract_ip6(void *data, void *data_end, struct bpf_sock_tuple *tuple) {

}

static __always_inline int skb_extract_tuple(struct __sk_buff *skb, struct bpf_sock_tuple *tuple)
{
        void *data_end = (void *)(uint64_t)(skb->data_end);
        void *data = (void *)(uint64_t)(skb->data);
        if ((data + sizeof(struct ethhdr)) > data_end)
                return -1;
        struct ethhdr *eth = data;
        switch (eth->h_proto) {
                case ETH_P_IP:
                        return skb_extract_ip4(data, data_end, tuple);
                case ETH_P_IPV6:
                        return skb_extract_ip6(data, data_end, tuple);
                default:
                        return -1;
        }
}

SEC("tc")
int tc_ingress_socket_redirect(struct __sk_buff *skb) {
        bpf_skb_pull_data(skb, 0);

        struct bpf_sock_tuple tuple = {0};

        if (skb_extract_tuple(skb, &tuple) == -1)
                return TC_ACT_OK;

        uint64_t *sock = bpf_map_lookup_elem(&accepted_sockets, &tuple);
        if (!sock)
                return TC_ACT_OK;

        if (!bpf_sk_redirect_map(skb, &accepted_sockets, (__u32)(uint64_t)&tuple, 0))
                return TC_ACT_SHOT;

        return TC_ACT_OK;
};
