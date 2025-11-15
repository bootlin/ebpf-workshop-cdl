#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

SEC("tc")
int dns_filter(struct __sk_buff *skb)
{
	struct ethhdr ethhdr;
	int ret;

	/* Load the Ethernet header */
	ret = bpf_skb_load_bytes(skb, 0, &ethhdr, sizeof(ethhdr));
	if (ret)
		return TC_ACT_OK;

	/* Let any frame that isn't IPv4 or IPv6 pass */
	if (ethhdr.h_proto != __bpf_constant_htons(ETH_P_IP) &&
	    ethhdr.h_proto != __bpf_constant_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

