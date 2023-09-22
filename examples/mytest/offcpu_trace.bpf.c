// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "offcpu_trace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define _(P)                                                                   \
    ({                                                                     \
        typeof(P) val;                                                 \
        bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
        val;                                                           \
    })

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/*
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct key_t);
    __type(value, u64);
    __uint(max_entries, 10000);
} counts SEC(".maps");
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10000);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10000);
} stackmap SEC(".maps");

#define MINBLOCK_US (10000)
#define SKIP_DEPTH  (1)
#define STACKID_FLAGS (SKIP_DEPTH | BPF_F_FAST_STACK_CMP)

//SEC("tp/sched/sched_switch")
//int handle_event(struct sched_sched_switch_args *ctx)
SEC("kprobe/finish_task_switch")
int handle_event(struct pt_regs *ctx)
{
    struct task_struct *prev = (void *) PT_REGS_PARM1(ctx);
    struct event *e;
    u64 delta, ts, *tsp;
 //   u32 prev_pid = ctx->prev_pid, next_pid = ctx->next_pid;
    u32 prev_pid = _(prev->pid), next_pid = (u32)bpf_get_current_pid_tgid();
    long stkid;

    ts = bpf_ktime_get_ns();
    if (prev_pid != 0) {
        bpf_map_update_elem(&start, &prev_pid, &ts, BPF_ANY);
    }

    if (next_pid == 0)
        return 0;

    tsp = bpf_map_lookup_elem(&start, &next_pid);
    if (!tsp)
        return 0;

    delta = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &next_pid);
    delta = delta / 1000;
    if (delta < MINBLOCK_US)
        return 0;

    stkid = bpf_get_stackid(ctx, &stackmap, STACKID_FLAGS);

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    //memcpy(&e->comm, ctx->next_comm, TASK_COMM_LEN);
    e->ts = ts;
    e->pid = next_pid;
    e->offtime = delta;
    e->stkid = stkid;

    bpf_ringbuf_submit(e, 0);

	return 0;
}
