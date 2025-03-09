#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/in.h>
#include <bcc/helpers.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

// Capture 40 bytes only (20 bytes IP header & 20 bytes TCP header + 12 bytes TCP options)
#define PAYLOAD_SIZE 66
BPF_PERF_OUTPUT(debug_events);

struct data_t {
    __u64 timestamp;
    __u8 payload[PAYLOAD_SIZE];
};

// Define the XDP program function, xdp_packet_counter
// This function is triggered for every incoming packet on the attached network interface
int test(struct xdp_md *ctx, struct __sk_buff *skb) {

    // Extract the end of the packet data from the metadata struct
    void *data_end = (void *)(long)ctx->data_end;

    // Extract the start of the packet data from the metadata struct
    void *data = (void *)(long)ctx->data;

    // Get a pointer to the Ethernet header of the packet
    struct ethhdr *eth = data;

    // If the Ethernet header extends beyond the end of the packet data, pass the packet
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // If the Ethernet header does not indicate an IP packet, pass the packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Get a pointer to the IP header of the packet
    struct iphdr *iph = (struct iphdr *)(data + ETH_HLEN);

    // If the IP header extends beyond the end of the packet data, pass the packet
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    struct data_t pkt = {};
    
    
    if (iph->protocol == IPPROTO_TCP) {
        void *transport_header = (void *)(iph + 1);

        struct tcphdr *tcp = transport_header;

        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // Exclude first 14 bytes to remove raw eth header
        bpf_probe_read_kernel(pkt.payload, PAYLOAD_SIZE, (void *)(data));

        u64 ts = bpf_ktime_get_ns();

        pkt.timestamp = ts;

        debug_events.perf_submit(ctx, &pkt, sizeof(pkt));
    }

    return XDP_PASS;
}