CC=${CROSS_COMPILE}gcc

all: dns_filter.bpf.o

dns_filter: dns_filter.c dns_filter.skel.h
	$(CC) $< -lbpf -o $@

tool: dns_filter

%.bpf.o: %.bpf.c
	clang -Wall -Werror -Wextra -target bpf -g -O2 -c $< -o $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< name $* > $@

clean:
	rm -rf *.o *.skel.h dns_filter

.PHONY:clean
.PHONY:tool
