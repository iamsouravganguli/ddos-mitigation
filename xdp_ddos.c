#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>

#define PACKET_THRESHOLD 2000

// Key for the flow map: source IP address
struct flow_key {
    __u32 saddr;
};

// Value for the flow map: packet count
struct flow_metrics {
    __u64 packet_count;
};

// BPF hash map to store packet counts for each source IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_map SEC(".maps");

// BPF ring buffer to send events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Data structure for the event sent to userspace
struct event {
    __u32 saddr;
    __u64 packet_count;
};

SEC("xdp_ddos")
int xdp_ddos_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    struct flow_key key = { .saddr = ip->saddr };
    struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_map, &key);

    if (!metrics) {
        struct flow_metrics new_metrics = { .packet_count = 1 };
        bpf_map_update_elem(&flow_map, &key, &new_metrics, BPF_ANY);
    } else {
        __u64 *count = &metrics->packet_count;
        (void)bpf_atomic_add(count, 1);

        if (*count > PACKET_THRESHOLD) {
            struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
            if (e) {
                e->saddr = ip->saddr;
                e->packet_count = *count;
                bpf_ringbuf_submit(e, 0);
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";