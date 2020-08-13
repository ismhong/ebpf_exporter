#include "bpf.h"
#include "bpf_helpers.h"

// Max temperal entries to keep in-flight record
#define MAX_ENTRY (10240)

// Max number of disks we expect to see on the host
#define MAX_DISKS (255)

// 27 buckets for latency, max range is 33.6s .. 67.1s
#define MAX_LATENCY_SLOT (26)

// 16 buckets per disk in kib, max range is 16mib .. 32mib
#define MAX_SIZE_SLOT (15)

// function for device information from blkdev.h
#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)
#define MAJOR(dev)	((__u32) ((dev) >> MINORBITS))
#define MINOR(dev)	((__u32) ((dev) & MINORMASK))

static inline __u32 new_encode_dev(__u32 dev)
{
	__u32 major = MAJOR(dev);
	__u32 minor = MINOR(dev);
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

struct block_rq_issue_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u32 common_pid;

    __u32 dev;
    __u64 sector;
    __u32 nr_sector;
    __u32 bytes;
    __u8 rwbs[8];
    __u8 comm[16];
};

struct block_rq_complete_args {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u32 common_pid;

    __u32 dev;
    __u64 sector;
    __u32 nr_sector;
    __s32 error;
    __u8 rwbs[8];
};

struct disk_key {
    __u32 dev;
    __u8 op;
    __u64 slot;
};

struct start_key {
    __u32 dev;
    __u64 sector;
};

struct start_val {
    __u64 start;
    __u64 bytes;
};

// Histograms to record latencies
BPF_MAP_DEF(io_latency) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = (MAX_LATENCY_SLOT + 2) * MAX_DISKS,
    .key_size = sizeof(struct disk_key),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(io_latency);

// Histograms to record sizes
BPF_MAP_DEF(io_size) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = (MAX_SIZE_SLOT + 2) * MAX_DISKS,
    .key_size = sizeof(struct disk_key),
    .value_size = sizeof(__u64),
};
BPF_MAP_ADD(io_size);

// Hash map to temperal record
BPF_MAP_DEF(start_record) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .max_entries = MAX_ENTRY,
    .key_size = sizeof(struct start_key),
    .value_size = sizeof(struct start_val),
};
BPF_MAP_ADD(start_record);

SEC("tracepoint/block/block_rq_issue")
int block_rq_issue(struct block_rq_issue_args *args) {
    __u32 bytes;
    __u8 comm[16];
    struct start_key entry = {};
    struct start_val entry_val = {};

    bpf_probe_read(&entry.dev, sizeof(__u32), &args->dev);
    bpf_probe_read(&entry.sector, sizeof(__u64), &args->sector);
    bpf_probe_read(&bytes, sizeof(__u32), &args->bytes);
    bpf_probe_read_str(&comm, sizeof(comm), &args->comm);

    if (entry.dev == 0) {
        return 0;
    }

    if (entry.sector == -1) {
        entry.sector = 0;
    }

    entry_val.start = bpf_ktime_get_ns();
    entry_val.bytes = bytes;

    bpf_map_update_elem(&start_record, &entry, &entry_val, BPF_ANY);

    /*bpf_printk("block_rq_issue by [%s] size->%d\n", comm, bytes);*/
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int block_rq_complete(struct block_rq_complete_args *args) {
    struct start_key entry = {};
    struct start_val *entry_val = 0;
    __u8 rwbs[8];

    bpf_probe_read(&entry.dev, sizeof(__u32), &args->dev);
    bpf_probe_read(&entry.sector, sizeof(__u64), &args->sector);
    bpf_probe_read(&rwbs[0], sizeof(rwbs), &args->rwbs[0]);

    if (entry.sector == -1) {
        entry.sector = 0;
    }

    entry_val = (struct start_val *)bpf_map_lookup_elem(&start_record, &entry);
    if (!entry_val) {
        /*bpf_printk("Can't find start record\n");*/
        goto cleanup;
    }

    // Delta in microseconds
    __u64 delta = (bpf_ktime_get_ns() - entry_val->start) / 1000;

    // Latency histogram key
    __u64 latency_slot = bpf_log2l(delta);

    // Cap latency bucket at max value
    if (latency_slot > MAX_LATENCY_SLOT) {
        latency_slot = MAX_LATENCY_SLOT;
    }

    struct disk_key latency_key = {};
    latency_key.slot = latency_slot;
    latency_key.dev = new_encode_dev(entry.dev);

    // Size in kibibytes
    __u64 size_kib = entry_val->bytes / 1024;

    // Request size histogram key
    __u64 size_slot = bpf_log2(size_kib);

    // Cap latency bucket at max value
    if (size_slot > MAX_SIZE_SLOT) {
        size_slot = MAX_SIZE_SLOT;
    }

    struct disk_key size_key = {};
    size_key.slot = size_slot;
    size_key.dev = new_encode_dev(entry.dev);
    if (rwbs[0] == 'W' || rwbs[0] == 'S' || rwbs[0] == 'F' || rwbs[1] == 'W' || rwbs[1] == 'S' || rwbs[1] == 'F') {
        latency_key.op = 2;
        size_key.op    = 2;
    } else {
        latency_key.op = 1;
        size_key.op    = 1;
    }

    // Increment latency key
    __u64 new_latency_val = 1;
    __u64 *latency_val = (__u64 *)bpf_map_lookup_elem(&io_latency, &latency_key);
    if (latency_val) {
        new_latency_val = *latency_val + 1;
    }
    bpf_map_update_elem(&io_latency, &latency_key, &new_latency_val, 0);

    // Increment size key
    __u64 new_size_val = 1;
    __u64 *size_val = (__u64 *)bpf_map_lookup_elem(&io_size, &size_key);
    if (size_val) {
        new_size_val = *size_val + 1;
    }
    bpf_map_update_elem(&io_size, &size_key, &new_size_val, 0);

    // Increment sum keys
    latency_key.slot = MAX_LATENCY_SLOT + 1;
    new_latency_val = 1;
    latency_val = (__u64 *)bpf_map_lookup_elem(&io_latency, &latency_key);
    if (latency_val) {
        new_latency_val = *latency_val + delta;
    }
    bpf_map_update_elem(&io_latency, &latency_key, &new_latency_val, 0);

    size_key.slot = MAX_SIZE_SLOT + 1;
    new_size_val = 1;
    size_val = (__u64 *)bpf_map_lookup_elem(&io_size, &size_key);
    if (size_val) {
        new_size_val = *size_val + size_kib;
    }
    bpf_map_update_elem(&io_size, &size_key, &new_size_val, 0);

    bpf_printk("block_rq_complete op->%d size->%d kib latency->%d ns\n", size_key.op, size_kib, delta);

cleanup:
    bpf_map_delete_elem(&start_record, &entry);
    return 0;
}

char _license[] SEC("license") = "GPL";
