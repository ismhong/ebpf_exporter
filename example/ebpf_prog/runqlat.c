#include "bpf.h"
#include "bpf_helpers.h"
/*#include "kernel_config.h"*/
#include <linux/sched.h>

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT (26)

#define TASK_RUNNING (0)

// number of entry for recording pid
#define MAX_ENTRY (1024)

struct task_struct {
    // offset got from pahole for x86-64 5.4
    __u8                    padding1[16];
    __u64                   state;                /*    16     8 */
    __u8                    padding2[1264];       /* 1288-16-8 = 1264 */
    __u32                   pid;                  /*  1288     4 */
    __u32                   tgid;                 /*  1292     4 */
};

// Histograms to record latencies
BPF_MAP_DEF(run_queue_latency) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_LATENCY_SLOT + 2,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(run_queue_latency);

// Pid to enqueue time map
BPF_MAP_DEF(start_record) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_ENTRY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(start_record);

// Record enqueue timestamp
static int inline trace_enqueue(__u32 tgid, __u32 pid) {

    if (tgid == 0 && pid == 0) {
        // Skip swapper kthread
        return 0;
    }

    __u64 entry_val = bpf_ktime_get_ns();
    __u32 entry = pid;

    /*start.update(&pid, &ts);*/
    bpf_map_update_elem(&start_record, &entry, &entry_val, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sched_wakeup")
int handle__sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    /* TP_PROTO(struct task_struct *p) */
    struct task_struct *p = 0;
    __u32 tgid = 0;
    __u32 pid = 0;
    bpf_probe_read(&p, sizeof(void *), &ctx->args[0]);
    bpf_probe_read(&tgid, sizeof(__u32), &p->tgid);
    bpf_probe_read(&pid, sizeof(__u32), &p->pid);

    return trace_enqueue(tgid, pid);
}

SEC("raw_tracepoint/sched_wakeup_new")
int handle__sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
    /* TP_PROTO(struct task_struct *p) */
    struct task_struct *p = 0;
    __u32 tgid = 0;
    __u32 pid = 0;
    bpf_probe_read(&p, sizeof(void *), &ctx->args[0]);
    bpf_probe_read(&tgid, sizeof(__u32), &p->tgid);
    bpf_probe_read(&pid, sizeof(__u32), &p->pid);

    return trace_enqueue(tgid, pid);
}

// Calculate latency
SEC("raw_tracepoint/sched_switch")
int handle__sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    // Treat like an enqueue event and store timestamp
    //
    /* TP_PROTO(bool preempt, struct task_struct *prev,
     *      struct task_struct *next)
     */
    struct task_struct *prev = 0;
    struct task_struct *next = 0;
    __u64 state = 0;
    __u32 tgid = 0;
    __u32 pid = 0;
    bpf_probe_read(&prev, sizeof(void *), &ctx->args[1]);
    bpf_probe_read(&next, sizeof(void *), &ctx->args[2]);
    bpf_probe_read(&state, sizeof(__u64), &prev->state);
    bpf_probe_read(&tgid, sizeof(__u32), &prev->tgid);
    bpf_probe_read(&pid, sizeof(__u32), &prev->pid);

    if (state == TASK_RUNNING) {
        trace_enqueue(tgid, pid);
    }

    bpf_probe_read(&pid, sizeof(__u32), &next->pid);

    // Fetch timestamp and calculate delta
    /*u64 *tsp = start.lookup(&pid);*/
    __u64 *tsp = bpf_map_lookup_elem(&start_record, &pid);
    if (tsp == 0) {
        // Missed enqueue
        if (pid) {
        bpf_printk("Missing enqueue, pid-> %d\n", pid);
        }
        return 0;
    }
    // Latency in microseconds
    __u64 latency_us = (bpf_ktime_get_ns() - *tsp) / 1000;
    // Latency histogram key
    __u64 latency_slot = bpf_log2l(latency_us);
    // Cap latency bucket at max value
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }
    // Increment bucket key
    /*run_queue_latencty.increment(latency_slot);*/
    __u64 new_latency_val = 1;
    __u64 *latency_val = (__u64 *)bpf_map_lookup_elem(&run_queue_latency, &latency_slot);
    if (latency_val) {
        new_latency_val = *latency_val + 1;
    }
    bpf_map_update_elem(&run_queue_latency, &latency_slot, &new_latency_val, 0);

    // Increment sum key
    /*run_queue_latencty.increment(max_latency_slot + 1, latency_us);*/
    latency_slot = MAX_LATENCY_SLOT + 1;
    new_latency_val = 1;
    latency_val = (__u64 *)bpf_map_lookup_elem(&run_queue_latency, &latency_slot);
    if (latency_val) {
        new_latency_val = *latency_val + latency_us;
    }
    bpf_map_update_elem(&run_queue_latency, &latency_slot, &new_latency_val, 0);

    // Remove enqueued task
    /*start.delete(&pid);*/
cleanup:
    bpf_map_delete_elem(&start_record, &pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
