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

struct {
        __uint(type, BPF_MAP_TYPE_SOCKHASH);
        __uint(max_entries, 65535);
        __type(key, struct bpf_sock_tuple);
        __type(value, __u64);
} accepted_sockets SEC(".maps");

static __always_inline int skb_extract_tcp(struct __sk_buff *skb, uint32_t l4_off, struct bpf_sock_tuple *tuple) {

}

static __always_inline int skb_extract_udp(struct __sk_buff *skb, uint32_t l4_off, struct bpf_sock_tuple *tuple) {

}

static __always_inline int skb_extract_ip4(struct __sk_buff *skb, struct bpf_sock_tuple *tuple) {
        // if ((skb->data + ETH_HLEN) > skb->data_end)
        //         return -1;
        struct iphdr *ip4 = (struct iphdr *)(uint64_t)(skb->data + ETH_HLEN);
}

static __always_inline int skb_extract_ip6(struct __sk_buff *skb, struct bpf_sock_tuple *tuple) {

}

static __always_inline int skb_extract_tuple(struct __sk_buff *skb, struct bpf_sock_tuple *tuple)
{
        struct ethhdr *eth = (struct ethhdr *)(uint64_t)skb->data;
        switch (eth->h_proto) {
                case ETH_P_IP:
                        skb_extract_ip4(skb, tuple);
                        break;
                case ETH_P_IPV6:
                        skb_extract_ip6(skb, tuple);
                        break;
                default:
                        return -1;
        }
}

SEC("tc")
int tc_ingress_socket_redirect(struct __sk_buff *skb) {
        bpf_skb_pull_data(skb, 0);

        return TC_ACT_OK;
};