
#### `xdp_ddos.c` (Final Version with Spam Fix)
```c
// Use the BCC-specific proto header for compatibility with python3-bpfcc
#include <bcc/proto.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>

#define PACKET_THRESHOLD 2000

// Key for the maps: source IP address
struct flow_key {
    u32 saddr;
};

// Value for the flow map: packet count
struct flow_metrics {
    u64 packet_count;
};

// BPF hash map to store packet counts for each source IP
BPF_HASH(flow_map, struct flow_key, struct flow_metrics, 100000);

// BPF hash map to track IPs that have already been reported to userspace
BPF_HASH(reported_ips, struct flow_key, u32, 100000);

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
            // Check if we have already reported this IP.
            u32 *already_reported = reported_ips.lookup(&key);
            if (!already_reported) {
                // If not reported, send the alert.
                struct event *e = events.ringbuf_reserve(sizeof(struct event));
                if (e) {
                    e->saddr = ip->saddr;
                    e->packet_count = metrics->packet_count;
                    events.ringbuf_submit(e, 0);
                }
                
                // Mark this IP as reported so we don't send more alerts.
                u32 reported_flag = 1;
                reported_ips.update(&key, &reported_flag);
            }
            
            // Always drop the packet if over threshold.
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}