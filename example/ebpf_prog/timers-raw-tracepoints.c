#include "bpf.h"
#include "bpf_helpers.h"

// timer_list struct definition from kernel
struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct timer_list {
	/*
	 * All fields that change during normal runtime grouped to the
	 * same cacheline
	 */
	struct hlist_node	entry;
	unsigned long		expires;
	void			(*function)(struct timer_list *);
    __u32			flags;

#ifdef CONFIG_LOCKDEP
	struct lockdep_map	lockdep_map;
#endif
};

// Max temperal entries to keep in-flight record
#define MAX_ENTRY (1024)

BPF_MAP_DEF(counts) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_ENTRY,
    .key_size = sizeof(void *),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(counts);

SEC("raw_tracepoint/timer_start")
int timer_start(struct bpf_raw_tracepoint_args *ctx) {
    // TP_PROTO(struct timer_list *timer,
    //        unsigned long expires,
    //        unsigned int flags),
    struct timer_list *timer = 0;
    __u64 index = 0;

    bpf_probe_read(&timer, sizeof(void *), &ctx->args[0]);
    bpf_probe_read(&index, sizeof(__u64), &timer->function);

    // Find the function which create timer in map
    __u64 *count = (__u64 *)bpf_map_lookup_elem(&counts, &index);

    // Update map
    __u64 new_count = 1;
    if (count) {
        new_count = *count + 1;
    }
    bpf_map_update_elem(&counts, &index, &new_count, 0);
    /*bpf_printk("timer_start by %llx, count %d\n", index, new_count);*/

    return 0;
}

char _license[] SEC("license") = "GPL";
