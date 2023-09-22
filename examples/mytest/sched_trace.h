/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __SCHED_TRACE_H
#define __SCHED_TRACE_H

#define TASK_COMM_LEN	 16

#define MAX_STACK_DEPTH 16

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct sched_sched_switch_args {
    unsigned long long unused;
    char prev_comm[TASK_COMM_LEN];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[TASK_COMM_LEN];
    pid_t next_pid;
    int next_prio;
};


struct event {
    unsigned long ts;
    int cpuid;
	int prev_pid;
    int prev_prio;
    char prev_comm[TASK_COMM_LEN];
	int next_pid;
    int next_prio;
    char next_comm[TASK_COMM_LEN];
    int prev_state;
    __s32 prev_kstack_sz;
    __s32 prev_ustack_sz; 
    stack_trace_t prev_kstack;
    stack_trace_t prev_ustack;
    stack_trace_t next_kstack;
    stack_trace_t next_ustack;
};

#endif
