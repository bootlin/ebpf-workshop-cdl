#include "dns_filter.skel.h"
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct dns_filter_bpf *dns;
	int fd, ifindex, ret;
	int key;

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .priority = 1);

	if (argc < 2)
		return -1;

	dns = dns_filter_bpf__open_and_load();
	if (!dns)
		return -1;

	fd = bpf_program__fd(dns->progs.dns_filter);

	ifindex = if_nametoindex(argv[1]);

	hook.ifindex = ifindex;
	opts.prog_fd = fd;

	/* Warning : When hitting ctrl-c, we'll exit without having cleaned the
	 * TC qdisc. Run the following command to clean it up :
	 *
	 * sudo tc qdisc delete dev wlp0s20f3 parent ffff:fff
	 *
	 */
	ret = bpf_tc_hook_create(&hook);
	if (ret)
		return ret;

	ret = bpf_tc_attach(&hook, &opts);
	if (ret) {
		bpf_tc_hook_destroy(&hook);
		return ret;
	}

	/* Start here */

	/* Here you must call 'bpf_map_update_elem() to insert the denied
	 * domain to our map. Here's the prototype of the function :
	 *
	 * int bpf_map_update_elem (int fd,
	 *			    const void *key,
	 *			    const void *value,
	 *			    __u64 flags)
	 *
	 * The 'fd' parameter is a _file descriptor_ representing our map. We
	 * don't have to open it ourselves, as it's already done by libbpf. You
	 * can get it by calling bpf_map__fd(dns->maps.array).
	 *
	 * key and value represent the items we want to insert in the map.
	 * Your goal is to add the domain (key) "docs.ebpf.io" at index 0.
	 *
	 * Finally, pass BPF_ANyY as the flags.
	 *
	 * This function returns 0 on success.
	 *
	 * */

	/* Stop here */

	while (1) {
		sleep(1);
	}

	bpf_tc_detach(&hook, &opts);
	bpf_tc_hook_destroy(&hook);
	dns_filter_bpf__destroy(dns);

	return 0;
}
