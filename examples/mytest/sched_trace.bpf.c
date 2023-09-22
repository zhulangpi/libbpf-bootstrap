// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "sched_trace.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_switch")
int handle_event(struct sched_sched_switch_args *ctx)
{
    struct event *e;
	//int pid = bpf_get_current_pid_tgid() >> 32;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->cpuid = bpf_get_smp_processor_id();
    e->prev_pid = ctx->prev_pid;
    e->next_pid = ctx->next_pid;
    memcpy(&e->prev_comm, ctx->prev_comm, TASK_COMM_LEN);
    memcpy(&e->next_comm, ctx->next_comm, TASK_COMM_LEN);
    //bpf_get_current_comm(&e->prev_comm, sizeof(e->prev_comm));

    e->prev_kstack_sz = bpf_get_stack(ctx, e->prev_kstack, sizeof(e->prev_kstack), 0);
    e->prev_ustack_sz = bpf_get_stack(ctx, e->prev_ustack, sizeof(e->prev_ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(e, 0);
	//bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}

/*
SEC("tp/sched/sched_waking")
int handle_tp1(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	//bpf_printk("BPF triggered from PID %d.\n", pid);

	return 0;
}
*/
