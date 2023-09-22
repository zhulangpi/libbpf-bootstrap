/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __OFFCPU_TRACE_H
#define __OFFCPU_TRACE_H

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
    unsigned long long ts;
    int cpu;
	int pid;
    char comm[TASK_COMM_LEN];
    unsigned long long offtime;
    long stkid;
};

#endif
