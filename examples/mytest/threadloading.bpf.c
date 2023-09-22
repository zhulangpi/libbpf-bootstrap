// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "threadloading.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

enum {
    RUNTIME = 0,
    SWITCHIN_TS,
    LAST_TS,
    PERIOD_NS,
    MAX_ENTRIES,
};

struct { 
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(unsigned long long));
        __uint(max_entries, MAX_ENTRIES);
} percpu_vars SEC(".maps");

SEC("tp/sched/sched_switch")
int handle_event(struct sched_sched_switch_args *ctx)
{
    struct event *e;
    u64 ts = bpf_ktime_get_boot_ns();
    int loading;
	int pid = bpf_get_current_pid_tgid() >> 32;
    unsigned long long *runtime, *switchin_ts, *last_ts, *period_ns;
    int idx0 = RUNTIME, idx1 = SWITCHIN_TS, idx2 = LAST_TS, idx3 = PERIOD_NS;

    runtime = bpf_map_lookup_elem(&percpu_vars, &idx0);
    switchin_ts = bpf_map_lookup_elem(&percpu_vars, &idx1);
    last_ts = bpf_map_lookup_elem(&percpu_vars, &idx2);
    //period_ns = bpf_map_lookup_elem(&percpu_vars, &idx3);

    if (runtime && switchin_ts && last_ts)
        ;
    else
        return 0;

    if (ctx->prev_pid == 0) {
        *runtime += ts - *switchin_ts;
    } else if (ctx->next_pid == 0) {
        *switchin_ts = ts;
    }

    if (ts - *last_ts < 1000000000)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->cpuid = bpf_get_smp_processor_id();
    e->last_ts = *last_ts;
    e->ts = ts;
    e->runtime = *runtime;
    *runtime = 0;
    *last_ts = ts;
    bpf_ringbuf_submit(e, 0);

//    if (bpf_get_smp_processor_id() == runtime)
//	    bpf_printk("BPF triggered from PID %d.\n", runtime);

	return 0;
}

