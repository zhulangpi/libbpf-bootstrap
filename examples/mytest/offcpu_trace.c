// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "trace_helpers.h"
#include "offcpu_trace.h"
#include "offcpu_trace.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

static int stkmap_fd;

const char *argp_program_version = "offcpu_trace 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF offcpu_trace demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./offcpu_trace [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

#define PRINT_RAW_ADDR (1)
static void print_ksym(__u64 addr)
{                        
        struct ksym *sym;

        if (!addr)
                return;
        sym = ksym_search(addr);
        if (!sym) {
                printf("ksym not found. Is kallsyms loaded?\n");
                return;
        }

        if (PRINT_RAW_ADDR)
                printf("\t%16llx %s\n", addr, sym->name);
        else
                printf("\t%40s\n", sym->name);
}

static void print_stack(long stkid)
{
    __u64 ip[MAX_STACK_DEPTH] = {}; 
    int i;
 
    if (bpf_map_lookup_elem(stkmap_fd, &stkid, ip) != 0) {
        printf("---;");
    } else {
        for (i = MAX_STACK_DEPTH - 1; i >= 0; i--)
            print_ksym(ip[i]);
    }
    printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

    printf("%16s %6d  %llu.%llu: %lluus\n", e->comm, e->pid, e->ts/1000000000, e->ts%1000000000, e->offtime);
    print_stack(e->stkid);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct offcpu_trace_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

    load_kallsyms();

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = offcpu_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	//skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = offcpu_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    stkmap_fd = bpf_map__fd(skel->maps.stackmap);

	/* Attach tracepoints */
	err = offcpu_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	offcpu_trace_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
