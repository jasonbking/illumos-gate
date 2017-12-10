/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */
#include <inttypes.h>
#include <sys/debug.h>
#include <alloca.h>
#include <stdio.h>
#include <getopt.h>
#include <kstat.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>

#define	_(x) gettext(x)

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

#define	LINES 20	/* Number of lines between headers */

typedef struct kstat_field {
	char *ksf_name;
	int ksf_hint;
} kstat_field_t;

typedef struct kstat_instance {
	char ksi_name[KSTAT_STRLEN];
	int ksi_instance;
	kstat_t *ksi_ksp;
	uint64_t *ksi_data[2];
	hrtime_t ksi_snaptime[2];
	int ksi_gen;
	struct kstat_instance *ksi_next;
} kstat_instance_t;

enum {
	KSF_IFSPEED,
	KSF_IPACKETS64,
	KSF_NORCVBUF,
	KSF_NOXMTBUF,
	KSF_OBYTES64,
	KSF_OPACKETS64,
	KSF_RBYTES64
};

static kstat_field_t ks_fields[] = {
	{ "ifspeed" },
	{ "ipackets64" },
	{ "norcvbuf" },
	{ "noxmtbuf" },
	{ "obyte64" },
	{ "opackets64" },
	{ "rbytes64" },
	{ NULL, -1 },
};

static uint64_t interval;
static uint64_t count = 1;
static char **interfaces;
static boolean_t do_summary;
static boolean_t skip_zero;

static void
fatal(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	verr(EXIT_FAILURE, msg, ap);
	va_end(ap);
}

static void
usage(const char *name)
{
	(void) fprintf(stderr,
	     _("USAGE: %s [-hsz] [-i int[,int...]] [interval [count]]\n"
	    "   eg, nicstat           # print summary since boot\n"
	    "       nicstat 1         # print continually every 1 second\n"
	    "       nicstat 1 5       # print 5 times, every 1 second\n"
	    "       nicstat -s        # summary output\n"
	    "       nicstat -i e1000g # print e1000g only\n"), name);

	exit(EXIT_FAILURE);
}

static boolean_t
is_net(kstat_t *ksp)
{
	const char module[] = "link";
	const char class[] = "net";

	if (strcmp(ksp->ks_module, module) != 0)
		return (B_FALSE);

	if (strcmp(ksp->ks_class, class) != 0)
		return (B_FALSE);

	if (interfaces == NULL)
		return (B_TRUE);

	for (size_t i = 0; interfaces[i] != NULL; i++) {
		if (strcmp(ksp->ks_name, interfaces[i]) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

static int
kstat_field_hint(kstat_t *ksp, kstat_field_t *field)
{
	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
	int i;

	VERIFY3U(ksp->ks_type, ==, KSTAT_TYPE_NAMED);

	for (i = 0; i < ksp->ks_ndata; i++) {
		if (strcmp(field->ksf_name, nm[i].name) == 0)
			return (field->ksf_hint = i);
	}

	fatal("could not find field '%s' in %s:%d",
	    field->ksf_name, ksp->ks_name, ksp->ks_instance);

	return (0);
}

static int
kstat_instances_compare(const void *lhs, const void *rhs)
{
	kstat_instance_t *l = *((kstat_instance_t **)lhs);
	kstat_instance_t *r = *((kstat_instance_t **)rhs);
	int rval;

	if ((rval = strcmp(l->ksi_name, r->ksi_name)) != 0)
		return (rval);

	if (l->ksi_instance < r->ksi_instance)
		return (-1);

	if (l->ksi_instance > r->ksi_instance)
		return (1);

	return (0);
}

static uint64_t
kstat_rate(kstat_instance_t *ksi, size_t n, ...)
{
	int gen = ksi->ksi_gen;
	uint64_t sum = 0;
	uint64_t tdelta = ksi->ksi_snaptime[gen ^ 1] - ksi->ksi_snaptime[gen];
	va_list ap;

	va_start(ap, n);
	for (size_t i = 0; i < n; i++) {
		int idx = va_arg(ap, int);
		sum += ksi->ksi_data[gen ^ 1][idx] - ksi->ksi_data[gen][idx];
	}
	va_end(ap);

	return (((sum * (uint64_t)NANOSEC) + (tdelta / 2)) / tdelta);
}

static void
kstat_instances_update(kstat_ctl_t *kcp, kstat_instance_t **head,
    boolean_t (*interested)(kstat_t *))
{
	int ninstances = 0, i;
	kstat_instance_t **sorted, *ksi, *next;
	kstat_t *ksp;
	kid_t kid;

	if ((kid = kstat_chain_update(kcp)) == 0 && *head != NULL)
		return;

	if (kid == -1)
		fatal("failed to update kstat chain");

	for (ksi = *head; ksi != NULL; ksi = ksi->ksi_next)
		ksi->ksi_ksp = NULL;

	for (ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		kstat_instance_t *last = NULL;

		if (!interested(ksp))
			continue;

		/*
		 * Now look to see if we have this instance and name.  (Yes,
		 * this is a linear search; we're assuming that this list is
		 * modest in size.)
		 */
		for (ksi = *head; ksi != NULL; ksi = ksi->ksi_next) {
			last = ksi;

			if (ksi->ksi_instance != ksp->ks_instance)
				continue;

			if (strcmp(ksi->ksi_name, ksp->ks_name) != 0)
				continue;

			ksi->ksi_ksp = ksp;
			ninstances++;
			break;
		}

		if (ksi != NULL)
			continue;

		if ((ksi = malloc(sizeof (kstat_instance_t))) == NULL)
			fatal("could not allocate memory for stat instance");

		bzero(ksi, sizeof (kstat_instance_t));
		(void) strlcpy(ksi->ksi_name, ksp->ks_name, KSTAT_STRLEN);
		ksi->ksi_instance = ksp->ks_instance;
		ksi->ksi_ksp = ksp;
		ksi->ksi_next = NULL;

		if (last == NULL) {
			VERIFY3P(*head, ==, NULL);
			*head = ksi;
		} else {
			last->ksi_next = ksi;
		}

		ninstances++;
	}

	/*
	 * Now we know how many instances we have; iterate back over them,
	 * pruning the stale ones and adding the active ones to a holding
	 * array in which to sort them.
	 */
	sorted = (void *)alloca(ninstances * sizeof (kstat_instance_t *));
	ninstances = 0;

	for (ksi = *head; ksi != NULL; ksi = next) {
		next = ksi->ksi_next;

		if (ksi->ksi_ksp == NULL) {
			free(ksi);
		} else {
			sorted[ninstances++] = ksi;
		}
	}

	if (ninstances == 0) {
		*head = NULL;
		return;
	}

	qsort(sorted, ninstances, sizeof (kstat_instance_t *),
	    kstat_instances_compare);

	*head = sorted[0];

	for (i = 0; i < ninstances; i++) {
		ksi = sorted[i];
		ksi->ksi_next = i < ninstances - 1 ? sorted[i + 1] : NULL;
	}
}

void
kstat_instances_read(kstat_ctl_t *kcp, kstat_instance_t *instances,
    kstat_field_t *fields)
{
	kstat_instance_t *ksi;
	int i, nfields;

	for (nfields = 0; fields[nfields].ksf_name != NULL; nfields++)
		continue;

	for (ksi = instances; ksi != NULL; ksi = ksi->ksi_next) {
		kstat_t *ksp = ksi->ksi_ksp;

		if (ksp == NULL)
			continue;

		if (kstat_read(kcp, ksp, NULL) == -1) {
			if (errno == ENXIO) {
				/*
				 * Our kstat has been removed since the update;
				 * NULL it out to prevent us from trying to read
				 * it again (and to indicate that it should not
				 * be displayed) and drive on.
				 */
				ksi->ksi_ksp = NULL;
				continue;
			}

			fatal("failed to read kstat %s:%d",
			    ksi->ksi_name, ksi->ksi_instance);
		}

		if (ksp->ks_type != KSTAT_TYPE_NAMED) {
			fatal("%s:%d is not a named kstat", ksi->ksi_name,
			    ksi->ksi_instance);
		}

		if (ksi->ksi_data[0] == NULL) {
			size_t size = nfields * sizeof (uint64_t) * 2;
			uint64_t *data;

			if ((data = malloc(size)) == NULL)
				fatal("could not allocate memory");

			bzero(data, size);
			ksi->ksi_data[0] = data;
			ksi->ksi_data[1] = &data[nfields];
		}
		for (i = 0; i < nfields; i++) {
			kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
			kstat_field_t *field = &fields[i];
			int hint = field->ksf_hint;

			if (field->ksf_name == NULL)
				continue;

			if (hint < 0 || hint >= ksp->ks_ndata ||
			    strcmp(field->ksf_name, nm[hint].name) != 0) {
				hint = kstat_field_hint(ksp, field);
			}

			ksi->ksi_data[ksi->ksi_gen][i] = nm[hint].value.ui64;
		}

		ksi->ksi_snaptime[ksi->ksi_gen] = ksp->ks_snaptime;
		ksi->ksi_gen ^= 1;
	}
}

static void
parse_interfaces(char *str)
{
	char *p = str;
	size_t n = 1;

	while (p[0] != '\0') {
		if (p[0] == ',')
			n++;
		p++;
	}

	if ((interfaces = calloc(n + 1, sizeof (char *))) == NULL)
		fatal("calloc");

	n = 0;
	for (p = strtok(str, ","); p != NULL; p = strtok(NULL, ",")) {
		if ((interfaces[n++] = strdup(p)) == NULL)
			fatal("strdup");
	}
}

static uint64_t
parse_int(const char *str)
{
	uint64_t val = 0;

	errno = 0;
	val = strtoull(str, NULL, 10);
	if (errno != 0)
		fatal(_("'%s' is not a valid number"), str);

	return (val);
}

static void
print_header(void)
{
	if (do_summary) {
		(void) printf("%8s %12s %14s %14s\n", "Time", "Int", "rKB/s",
		    "wKB/s");
	} else {
		(void) printf("%8s %12s %7s %7s %7s %7s %7s %7s %6s %5s\n",
		    "Time", "Int", "rKB/s", "wKB/s", "rPk/s", "wPk/s", "rAvs",
		    "wAvs", "%Util", "Sat");
	}
}

static uint64_t
tdelta(kstat_instance_t *ksi)
{
	int gen = ksi->ksi_gen;

	return (ksi->ksi_snaptime[gen ^ 1] - ksi->ksi_snaptime[gen]);
}

static uint64_t
vdelta(kstat_instance_t *ksi, size_t n, va_list ap)
{
	uint64_t sum = 0;

	for (size_t i = 0; i < n; i++) {
		int idx = va_arg(ap, int);

		sum += ksi->ksi_data[ksi->ksi_gen ^ 1][idx] -
		    ksi->ksi_data[ksi->ksi_gen][idx];
	}
	return (sum);
}

static uint64_t
delta(kstat_instance_t *ksi, size_t n, ...)
{
	uint64_t sum;
	va_list ap;

	va_start(ap, n);
	sum = vdelta(ksi, n, ap);
	va_end(ap);

	return (sum);
}

uint64_t
rate(kstat_instance_t *ksi, int field)
{
	uint64_t sum = 0;
	uint64_t t = tdelta(ksi);

	sum = delta(ksi, 1, field);

	return (((sum * (uint64_t)NANOSEC) + (t / 2)) / t);
}

static boolean_t
print_instance(kstat_instance_t *ksi)
{
	uint64_t rbps = rate(ksi, KSF_RBYTES64);
	uint64_t wbps = rate(ksi, KSF_OBYTES64);
	uint64_t rpps = rate(ksi, KSF_OPACKETS64);
	uint64_t wpps = rate(ksi, KSF_IPACKETS64);

	if (rbps + wbps == 0 && skip_zero)
		return (B_FALSE);

	double ravs = (double)rbps / rpps;
	double wavs = (double)wbps / wpps;
	uint64_t sat = delta(ksi, 2, KSF_NORCVBUF, KSF_NOXMTBUF);
	double satr = (double)(sat * NANOSEC) / tdelta(ksi);

	return (B_TRUE);
}

void
intr(int sig __unused)
{}

int
main(int argc, char * const argv[])
{
	kstat_ctl_t *kcp;
	kstat_instance_t *instances = NULL;
	struct itimerval itimer = { 0 };
	struct sigaction act;
	sigset_t set;
	uint64_t i = 0, line = 0;
	int c;

	while ((c = getopt(argc, argv, "hi:sz")) != -1) {
		switch (c) {
		case 'h':
			usage(argv[0]);
			break;
		case 'i':
			parse_interfaces(optarg);
			break;
		case 's':
			do_summary = B_TRUE;
			break;
		case 'z':
			skip_zero = B_TRUE;
			break;
		}
	}

	if (optind > argc) {
		interval = parse_int(argv[optind]);
		count = UINT64_MAX;
	}

	if (optind + 1 > argc)
		count = parse_int(argv[optind + 1]);

	if ((kcp = kstat_open()) == NULL)
		fatal(_("Could not open /dev/kstat"));

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;
	(void) sigaction(SIGALRM, &act, NULL);

	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGALRM);
	(void) sigprocmask(SIG_BLOCK, &set, NULL);

	itimer.it_value.tv_sec = interval;
	itimer.it_interval.tv_sec = interval;

	(void) sigemptyset(&set);

	while (i++ < count) {
		kstat_instance_t *inst;

		kstat_instances_update(kcp, &instances, is_net);
		kstat_instances_read(kcp, instances, ks_fields);

		line = 0;
		for (inst = instances; inst != NULL; inst = inst->ksi_next) {
			if (line == 0)
				print_header();

			if (print_instance(inst))
				line++;

			line = line % LINES;
		}

		(void) fputc('\n', stdout);
		(void) sigsuspend(&set);
	}

	return (0);
}
