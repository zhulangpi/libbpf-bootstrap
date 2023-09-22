// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include "threadloading.h"
#include "threadloading.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "sched_trace 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] = "BPF sched_trace demo application.\n"
				"\n"
				"It traces process start and exits and shows associated \n"
				"information (filename, process duration, PID and PPID, etc).\n"
				"\n"
				"USAGE: ./sched_trace [-d <min-duration-ms>] [-v]\n";

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

static unsigned int nr_cpus, cpumask, cpumap;

static float total_cpu;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
    float cpu = 100.0 * e->runtime / (e->ts - e->last_ts);

//	printf("%d %llu %llu %llu\n", e->cpuid, e->last_ts, e->ts, e->runtime );
    printf("cpu%d loading: %03.3f\n", e->cpuid, cpu);
    total_cpu += cpu;
    cpumap |= 1 << e->cpuid;
    if (cpumap == cpumask) {
        cpumap = 0;
        printf("----------total cpu: %03.3f------------\n", total_cpu / nr_cpus);
        total_cpu = 0;
    }

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct threadloading_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

    nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    cpumask = (1 << nr_cpus) - 1;

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);


	fprintf(stderr, "\n\nthreadloading_bpf__open start\n");
	/* Load and verify BPF application */
	skel = threadloading_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	//skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	fprintf(stderr, "\n\nthreadloading_bpf__open success\n");
	/* Load & verify BPF programs */
	err = threadloading_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	fprintf(stderr, "\n\nthreadloading_bpf__load success\n");
	/* Attach tracepoints */
	err = threadloading_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	fprintf(stderr, "\n\nthreadloading_bpf__attach success\n");

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 1000 /* timeout, ms */);
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
	threadloading_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
