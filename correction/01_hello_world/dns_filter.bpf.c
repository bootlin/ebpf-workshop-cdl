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
	bpf_printk("Hello, world !\n");

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

