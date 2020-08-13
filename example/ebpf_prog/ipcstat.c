#include "bpf.h"
#include "bpf_helpers.h"

#define MAX_CPUS (4)

BPF_MAP_DEF(instructions) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .max_entries = MAX_CPUS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(instructions);

/*BPF_ARRAY(cycles, u64, max_cpus);*/
BPF_MAP_DEF(cycles) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .max_entries = MAX_CPUS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(cycles);

SEC("perf_event/on_cpu_instruction")
int on_cpu_instruction(struct bpf_perf_event_data *ctx) {
    /*instructions.increment(bpf_get_smp_processor_id(), ctx->sample_period);*/
    __u32 index = (__u32)bpf_get_smp_processor_id();
    __u64 *ins = (__u64 *)bpf_map_lookup_elem(&instructions, &index);
    __u64 new_ins;

    if (ins && ctx) {
        new_ins = *ins + ctx->sample_period;
        bpf_map_update_elem(&instructions, &index, &new_ins, 0);
        /*bpf_printk("[cpu %d] instructions %lld\n", bpf_get_smp_processor_id(), ctx->sample_period);*/
    }
    return 0;
}

SEC("perf_event/on_cpu_cycle")
int on_cpu_cycle(struct bpf_perf_event_data *ctx) {
    /*cycles.increment(bpf_get_smp_processor_id(), ctx->sample_period);*/
    __u32 index = (__u32)bpf_get_smp_processor_id();
    __u64 *ins = (__u64 *)bpf_map_lookup_elem(&cycles, &index);
    __u64 new_ins;
    if (ins && ctx) {
        new_ins = *ins + ctx->sample_period;
        bpf_map_update_elem(&cycles, &index, &new_ins, 0);
        /*bpf_printk("[cpu %d] cycles %lld\n", bpf_get_smp_processor_id(), ctx->sample_period);*/
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
