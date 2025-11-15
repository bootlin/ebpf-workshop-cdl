#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

struct dnshdr {
        __be16 trans_id;
        __be16 flags;
        __be16 nr_quest;
        __be16 nr_answ;
        __be16 nr_auth_rr;
        __be16 add_rr;
};

SEC("tc")
int dns_filter(struct __sk_buff *skb)
{
	unsigned int offset = 0;
	struct ethhdr ethhdr;
	struct udphdr udphdr;
	struct dnshdr dnshdr;
	char l4_proto;
	int ret;

	/* Load the Ethernet header */
	ret = bpf_skb_load_bytes(skb, 0, &ethhdr, sizeof(ethhdr));
	if (ret)
		return TC_ACT_OK;

	offset += sizeof(ethhdr);

	/* Let any frame that isn't IPv4 or IPv6 pass */
	if (ethhdr.h_proto != __bpf_constant_htons(ETH_P_IP) &&
	    ethhdr.h_proto != __bpf_constant_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	/* IPv4 handling */
	if (ethhdr.h_proto == __bpf_constant_htons(ETH_P_IP)) {
		struct iphdr iphdr;

		ret = bpf_skb_load_bytes(skb, offset, &iphdr, sizeof(iphdr));
		if (ret)
			return TC_ACT_OK;

		l4_proto = iphdr.protocol;

		offset += sizeof(iphdr);

	/* IPv6 handling */
	} else {
		struct ipv6hdr ipv6hdr;

		ret = bpf_skb_load_bytes(skb, offset, &ipv6hdr, sizeof(ipv6hdr));
		if (ret)
			return TC_ACT_OK;

		l4_proto = ipv6hdr.nexthdr;

		offset += sizeof(ipv6hdr);
	}

	/* Pass everything that isn't UDP */
	if (l4_proto != IPPROTO_UDP)
		return TC_ACT_OK;

	/* Load UDP header */
	ret = bpf_skb_load_bytes(skb, offset, &udphdr, sizeof(udphdr));
	if (ret)
		return TC_ACT_OK;

	/* Pass anything that doesn't have destination port 53 (dns) */
	if (udphdr.dest != __bpf_constant_htons(53))
		return TC_ACT_OK;

	offset += sizeof(udphdr);

	/* Load DNS header */
	ret = bpf_skb_load_bytes(skb, offset, &dnshdr, sizeof(dnshdr));
	if (ret)
		return TC_ACT_OK;

	/* Pass everything that isn't a Query */
	if (dnshdr.flags & __bpf_constant_htons(0x0001))
		return TC_ACT_OK;

	offset += sizeof(dnshdr);

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

