/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __THREADLOADING_H
#define __THREADLOADING_H

#define TASK_COMM_LEN	 16

#define MAX_STACK_DEPTH 16

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct sched_sched_switch_args {
    unsigned long long unused;
#if 0
    unsigned int unused_arm64;
#endif
    char prev_comm[TASK_COMM_LEN];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[TASK_COMM_LEN];
    pid_t next_pid;
    int next_prio;
};


struct event {
    int cpuid;
    unsigned long long last_ts;
    unsigned long long ts;
    unsigned long long runtime;
};

#endif
