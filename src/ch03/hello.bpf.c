#include <linux/bpf.h>  // 1.
#include <bpf/bpf_helpers.h>

int counter = 0;    // 2.

SEC("xdp")          // 3.
int hello(struct xdp_md *ctx) {     // 4.
    bpf_printk("Hello World %d", counter);
    counter++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";     // 5.