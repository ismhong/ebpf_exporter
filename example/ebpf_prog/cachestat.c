#include "bpf.h"
#include "bpf_helpers.h"

// Max temperal entries to keep in-flight record
#define MAX_ENTRY (1024)

BPF_MAP_DEF(counts) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_ENTRY,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(counts);

void inline do_count(struct pt_regs *ctx) {
    __u64 index = PT_REGS_IP(ctx) - 1;

    // Find the function which create timer in map
    __u64 *count = (__u64 *)bpf_map_lookup_elem(&counts, &index);

    // Update map
    __u64 new_count = 1;
    if (count) {
        new_count = *count + 1;
    }
    bpf_map_update_elem(&counts, &index, &new_count, 0);
    bpf_printk("cache operation called by %llx, count %d\n", index, new_count);
}

SEC("kprobe/add_to_page_cache_lru")
int add_to_page_cache_lru(struct pt_regs *ctx) {
    do_count(ctx);
    return 0;
}

SEC("kprobe/mark_page_accessed")
int mark_page_accessed(struct pt_regs *ctx) {
    do_count(ctx);
    return 0;
}

SEC("kprobe/account_page_dirtied")
int account_page_dirtied(struct pt_regs *ctx) {
    do_count(ctx);
    return 0;
}

SEC("kprobe/mark_buffer_dirty")
int mark_buffer_dirty(struct pt_regs *ctx) {
    do_count(ctx);
    return 0;
}

char _license[] SEC("license") = "GPL";
