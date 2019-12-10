#include <linux/types.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include "bpf_helpers.h"

#ifdef DEBUG
/* /sys/kernel/debug/tracing/trace_pipe */
#define bpf_trace(fmt, ...)                             \
    ({                                                  \
        char f[] = fmt;                                 \
        bpf_trace_printk(f, sizeof(f), ##__VA_ARGS__);  \
    })
#else
#define bpf_trace(fmt, ...) do { } while (0)
#endif

SEC("action")
int tcp_bpf_main(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
    void *data_end = (void *)(long)skb->data_end;

    if ((void *)(tcphdr + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP) ||
        iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    /* bitfields are not addressable*/
    tcphdr->fin ^= 1;
    tcphdr->syn ^= 1;
    tcphdr->rst ^= 1;
    tcphdr->psh ^= 1;
    tcphdr->ack ^= 1;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
