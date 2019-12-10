CFLAGS += -I ./include -O2 -target bpf

all: tcp_flags ebpf_printk

ebpf_printk: ebpf_printk/ebpf_printk.c
	clang $(CFLAGS) -c $< -o $@.o

tcp_flags: tcp_flags/tcp_flags.c
	clang $(CFLAGS) -c $< -o $@.o

clean:
	-rm -f *.o

.PHONY: clean tcp_flags ebpf_printk
