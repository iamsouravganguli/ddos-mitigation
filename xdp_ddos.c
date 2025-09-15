// Use the BCC-specific proto header for compatibility with python3-bpfcc
#include <bcc/proto.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>

#define PACKET_THRESHOLD 2000

// Key for the flow map: source IP address
struct flow_key {
    u32 saddr;
};

// Value for the flow map: packet count
struct flow_metrics {
    u64 packet_count;
};

// BPF hash map to store packet counts for each source IP
BPF_HASH(flow_map, struct flow_key, struct flow_metrics, 100000);

// BPF ring buffer to send events to userspace
BPF_RINGBUF_OUTPUT(events, 8); // 8 pages = 32KB

// Data structure for the event sent to userspace
struct event {
    u32 saddr;
    u64 packet_count;
};


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
    struct flow_metrics *metrics = flow_map.lookup(&key);

    if (!metrics) {
        struct flow_metrics new_metrics = { .packet_count = 1 };
        flow_map.update(&key, &new_metrics);
    } else {
        lock_xadd(&metrics->packet_count, 1);

        if (metrics->packet_count > PACKET_THRESHOLD) {
            struct event *e = events.ringbuf_reserve(sizeof(struct event));
            if (e) {
                e->saddr = ip->saddr;
                e->packet_count = metrics->packet_count;
                events.ringbuf_submit(e, 0);
            }
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}