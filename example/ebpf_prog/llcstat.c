#include "bpf.h"
#include "bpf_helpers.h"

#define MAX_CPUS (4)

BPF_MAP_DEF(misses) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .max_entries = MAX_CPUS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(misses);

/*BPF_ARRAY(references, u64, max_cpus);*/
BPF_MAP_DEF(references) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .max_entries = MAX_CPUS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(references);

SEC("perf_event/on_cache_miss")
int on_cpu_instruction(struct bpf_perf_event_data *ctx) {
    __u32 index = (__u32)bpf_get_smp_processor_id();
    __u64 *ins = (__u64 *)bpf_map_lookup_elem(&misses, &index);
    __u64 new_ins;

    if (ins && ctx) {
        new_ins = *ins + ctx->sample_period;
        bpf_map_update_elem(&misses, &index, &new_ins, 0);
        /*bpf_printk("[cpu %d] misses %lld\n", bpf_get_smp_processor_id(), ctx->sample_period);*/
    }
    return 0;
}

SEC("perf_event/on_cache_reference")
int on_cpu_cycle(struct bpf_perf_event_data *ctx) {
    __u32 index = (__u32)bpf_get_smp_processor_id();
    __u64 *ins = (__u64 *)bpf_map_lookup_elem(&references, &index);
    __u64 new_ins;
    if (ins && ctx) {
        new_ins = *ins + ctx->sample_period;
        bpf_map_update_elem(&references, &index, &new_ins, 0);
        /*bpf_printk("[cpu %d] references %lld\n", bpf_get_smp_processor_id(), ctx->sample_period);*/
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
