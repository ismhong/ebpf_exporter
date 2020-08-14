#include "bpf.h"
#include "bpf_helpers.h"

// Max temperal entries to keep in-flight record
#define MAX_ENTRY (1024)

struct key_t {
    __u64 ip;
    char command[128];
};

BPF_MAP_DEF(counts) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_ENTRY,
    .key_size = sizeof(struct key_t),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(counts);

void inline do_count(struct pt_regs *ctx) {
    struct key_t key = { .ip = PT_REGS_IP(ctx) - 1 };
    bpf_get_current_comm(&key.command, sizeof(key.command));

    // Find the function which create timer in map
    __u64 *count = (__u64 *)bpf_map_lookup_elem(&counts, &key);

    // Update map
    __u64 new_count = (count)? *count + 1 : 1;
    bpf_map_update_elem(&counts, &key, &new_count, 0);

    /*bpf_printk("cache operation called by %s, count %d\n", key.command, new_count);*/
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
