// Use the BCC-specific proto header for compatibility
#include <bcc/proto.h>

// Standard Linux network headers for Ethernet and IP protocols
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>

// Define the threshold for packet counts from a single source.
// If a source IP exceeds this number of packets, it will be considered hostile.
#define PACKET_THRESHOLD 2000

// Defines the key for BPF maps, which is the source IP address.
// This allows us to track and identify traffic from unique sources.
struct flow_key {
    u32 saddr; // Source IP address
};

// Defines the value for the flow map, which is the packet count.
// This is used to measure the volume of traffic from a source.
struct flow_metrics {
    u64 packet_count; // Number of packets from this source
};

// --- BPF Maps ---
// These maps are used to store state and share data between the kernel and user space.

// A hash map for whitelisted IPs. Any IP in this list will be allowed to pass,
// bypassing all other checks. This is useful for trusted sources.
BPF_HASH(whitelist, struct flow_key, u32, 1024);

// A hash map for manually blocklisted IPs. Any IP in this list will be immediately
// dropped. This is for permanently blocking known malicious actors.
BPF_HASH(manual_blocklist, struct flow_key, u32, 10240);

// A hash map to dynamically track packet counts for each source IP.
// This is the core of the automatic DDoS detection mechanism.
BPF_HASH(flow_map, struct flow_key, struct flow_metrics, 100000);

// A hash map to keep track of IPs that have already been reported to user space.
// This prevents sending duplicate alerts for the same offending IP.
BPF_HASH(reported_ips, struct flow_key, u32, 100000);

// A ring buffer to send event notifications to the user space controller.
// This is how the kernel program communicates with the outside world.
BPF_RINGBUF_OUTPUT(events, 8);

// Defines the data structure for an event sent to user space.
// It includes the source IP and the packet count that triggered the event.
struct event {
    u32 saddr;
    u64 packet_count;
};

// This is the main XDP program that gets executed for each incoming packet.
int xdp_ddos_prog(struct xdp_md *ctx) {
    // Get pointers to the start and end of the packet data.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse the Ethernet header.
    struct ethhdr *eth = data;
    // Check if the packet is large enough to contain an Ethernet header.
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS; // Not a valid Ethernet frame, let it pass.
    }

    // Check if the packet is an IP packet.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Not an IP packet, let it pass.
    }

    // Parse the IP header.
    struct iphdr *ip = data + sizeof(*eth);
    // Check if the packet is large enough to contain an IP header.
    if ((void*)ip + sizeof(*ip) > data_end) {
        return XDP_PASS; // Not a valid IP packet, let it pass.
    }

    // Create a key with the source IP address to use in the BPF maps.
    struct flow_key key = { .saddr = ip->saddr };

    // 1. Check the whitelist first.
    // If the source IP is in the whitelist, always allow the packet.
    if (whitelist.lookup(&key)) {
        return XDP_PASS;
    }

    // 2. Check the manual blocklist.
    // If the source IP is in the manual blocklist, always drop the packet.
    if (manual_blocklist.lookup(&key)) {
        return XDP_DROP;
    }

    // 3. Perform automatic detection based on packet count.
    struct flow_metrics *metrics = flow_map.lookup(&key);

    if (!metrics) {
        // If this is the first time we see this IP, create a new entry in the flow map.
        struct flow_metrics new_metrics = { .packet_count = 1 };
        flow_map.update(&key, &new_metrics);
    } else {
        // If we have seen this IP before, atomically increment its packet count.
        lock_xadd(&metrics->packet_count, 1);

        // If the packet count exceeds the defined threshold, take action.
        if (metrics->packet_count > PACKET_THRESHOLD) {
            // Check if we have already reported this IP to user space.
            u32 *already_reported = reported_ips.lookup(&key);
            if (!already_reported) {
                // If not reported, send an event to the user space controller.
                struct event *e = events.ringbuf_reserve(sizeof(struct event));
                if (e) {
                    e->saddr = ip->saddr;
                    e->packet_count = metrics->packet_count;
                    events.ringbuf_submit(e, 0);
                }
                
                // Mark this IP as reported to avoid sending more alerts.
                u32 reported_flag = 1;
                reported_ips.update(&key, &reported_flag);
            }
            // Drop the packet as it has exceeded the rate limit.
            return XDP_DROP;
        }
    }

    // If the packet has not been dropped by any of the checks, let it pass.
    return XDP_PASS;
}
