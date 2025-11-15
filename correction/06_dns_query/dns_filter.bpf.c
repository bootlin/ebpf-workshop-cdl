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

/** parse_query() - Parse a DNS query
 * skb: The input skb
 * offset: The location of the first byte of the query in the skb
 * query: output parameter, the query will be stored in dotted notation.
 * max_len: size of the query buffer. DNS standard says max is 253.
 *
 * Returns: The number of characters in the query, a negative number otherwise
 */
static int parse_query(struct __sk_buff *skb, unsigned int offset, char *query, int max_len)
{
	unsigned int pos = 1;
	int ret, i;
	char c;

	if (!skb || !query || max_len <= 0 || max_len > 253)
		return -1;

	/* First byte is a label len, we skip it. */
	ret = bpf_skb_load_bytes(skb, offset, &c , 1);
	if (ret)
		return -1;

	while (c != '\0') {
		ret = bpf_skb_load_bytes(skb, offset + pos, &c , 1);
		if (ret)
			return -1;

		if ((c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9'))
			query[pos - 1] = c;
		else if (c != '\0')
			query[pos - 1] = '.';

		pos++;

		if (pos >= max_len || c == '\0')
			break;
	}

	return pos;
}

static int __strncmp(const void *m1, const void *m2, unsigned int len)
{
        const unsigned char *s1 = m1;
        const unsigned char *s2 = m2;
        int i, delta = 0;

        for (i = 0; i < len; i++) {
                delta = s1[i] - s2[i];
                if (delta || s1[i] == 0 || s2[i] == 0)
                        break;
        }
        return delta;
}

SEC("tc")
int dns_filter(struct __sk_buff *skb)
{
	const char *deny = "example.com";
	unsigned int offset = 0;
	char query[253] = {0};
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

	/* Extract the domain from the query */
	ret = parse_query(skb, offset, query, 253);
	if (ret < 0)
		return TC_ACT_OK;

	/* If it matches our denied domain, we immediately drop the packet */
	if (!__strncmp(query, deny, sizeof(deny)))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

