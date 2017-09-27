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

#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>
#include <libcmdutils.h>
#include <locale.h>
#include <kstat.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <stdarg.h>
#include <sys/debug.h>
#include "statcommon.h"

#define	_(x) gettext(x)

#ifndef ARRAY_SIZE
#define	ARRAY_SIZE(x)	(sizeof (x) / sizeof (x[0]))
#endif

typedef struct kstat_field {
	char *ksf_name;			/* name of stat if any */
	int ksf_hint;			/* index hint for field in kstat */
} kstat_field_t;

typedef struct kstat_instance {
	char ksi_name[KSTAT_STRLEN];	/* name of the underlying kstat */
	int ksi_instance;		/* instance identifier of this kstat */
	kstat_t *ksi_ksp;		/* pointer to the kstat */
	uint64_t *ksi_data[2];		/* pointer to two generations of data */
	hrtime_t ksi_snaptime[2];	/* hrtime for data generations */
	int ksi_gen;			/* current generation */
	struct kstat_instance *ksi_next; /* next in instance list */
} kstat_instance_t;

typedef enum colname {
	CN_TIME,
	CN_HITS,
	CN_MISS,
	CN_READ,
	CN_HITPCT,
	CN_MISSPCT,
	CN_DHIT,
	CN_DMIS,
	CN_DHITPCT,
	CN_DMISPCT,
	CN_PHIT,
	CN_PMIS,
	CN_PHITPCT,
	CN_PMISPCT,
	CN_MHIT,
	CN_MMIS,
	CN_MREAD,
	CN_MHITPCT,
	CN_MMISPCT,
	CN_ARCSZ,
	CN_C,
	CN_MFU,
	CN_MRU,
	CN_MFUG,
	CN_MRUG,
	CN_ESKIP,
	CN_MTXMIS,
	CN_DREAD,
	CN_PREAD,
	CN_L2HITS,
	CN_L2MISS,
	CN_L2READ,
	CN_L2HITPCT,
	CN_L2MISSPCT,
	CN_L2ASIZE,
	CN_L2SIZE,
	CN_L2BYTES
} colname_t;

/* Order should match colname_t */
static struct coldef {
	const char	*c_hdr;
	size_t		c_size;
	size_t		c_scale;
	const char	*c_desc;
} col_defs[] = {
	{ "time", 8, 0, "Time" },
	{ "hits", 5, 1000, "ARC reads per second " },
	{ "miss", 5, 1000, "ARC misses per second" },
	{ "read", 5, 1000, "Total ARC accesses per second" },
	{ "hit%", 4, 100, "ARC Hit percentage" },
	{ "miss%", 5, 100, "ARC miss percentage" },
	{ "dhit", 5, 1000, "Demand Data hits per second" },
	{ "dmis", 5, 1000, "Demand Data misses per second" },
	{ "dh%", 3, 100, "Demand Data hit percentage" },
	{ "dm%", 3, 100, "Demand Data miss percentage" },
	{ "phit", 5, 1000, "Prefetch hits per second" },
	{ "pmis", 5, 1000, "Prefetch misses per second" },
	{ "ph%", 3, 100, "Prefetch hits percentage" },
	{ "pm%", 3, 100, "Prefetch miss percentage" },
	{ "mhit", 5, 1000, "Metadata hits per second" },
	{ "mmis", 5, 1000, "Metadata misses per second" },
	{ "mread", 5, 1000, "Metadata accesses per second" },
	{ "mh%", 3, 100, "Metadata hit percentage" },
	{ "mm%", 3, 100, "Metadata miss percentage" },
	{ "arcsz", 5, 1024, "ARC Size" },
	{ "c", 5, 1024, "ARC Target Size" },
	{ "mfu", 5, 1000, "MFU List hits per second" },
	{ "mru", 5, 1000, "MRU List hits per second" },
	{ "mfug", 5, 1000, "MFU Ghost List hits per second" },
	{ "mrug", 5, 1000, "MRU Ghost List hits per second" },
	{ "eskip", 5, 1000, "evict_skip per second" },
	{ "mtxmis", 6, 1000, "mutex_miss per second" },
	{ "dread", 5, 1000, "Demand data accesses per second" },
	{ "pread", 5, 1000, "Prefetch accesses per second" },
	{ "l2hits", 6, 1000, "L2ARC hits per second" },
	{ "l2miss", 6, 1000, "L2ARC misses per second" },
	{ "l2read", 6, 1000, "Total L2ARC accesses per second" },
	{ "l2hit%", 6, 100, "L2ARC access hit percentage" },
	{ "l2miss%", 7, 100, "L2ARC access miss percentage" },
	{ "l2asize", 7, 1024, "Actual (compressed) size of the L2ARC" },
	{ "l2size", 6, 1024, "Size of the L2ARC" },
	{ "l2bytes", 7, 1024, "bytes read per second from the L2ARC" },
};
#define	NUM_VALS	(ARRAY_SIZE(col_defs))

typedef enum ks_fieldname {
	KSF_HITS,
	KSF_MISSES,
	KSF_DEMAND_DATA_HITS,
	KSF_DEMAND_METADATA_HITS,
	KSF_DEMAND_DATA_MISSES,
	KSF_DEMAND_METADATA_MISSES,
	KSF_PREFETCH_DATA_HITS,
	KSF_PREFETCH_METADATA_HITS,
	KSF_PREFETCH_DATA_MISSES,
	KSF_PREFETCH_METADATA_MISSES,
	KSF_SIZE,
	KSF_C,
	KSF_MFU_HITS,
	KSF_MRU_HITS,
	KSF_MRU_GHOST_HITS,
	KSF_MFU_GHOST_HITS,
	KSF_EVICT_SKIP,
	KSF_MUTEX_MISS,
	KSF_L2_HITS,
	KSF_L2_MISSES,
	KSF_L2_SIZE,
	KSF_L2_ASIZE,
	KSF_L2_READ_BYTES,
} ks_fieldname_t;

static kstat_field_t ks_fields[] = {
	{ "hits", -1},
	{ "misses", -1 },
	{ "demand_data_hits", -1 },
	{ "demand_metadata_hits", -1 },
	{ "demand_data_misses", -1 },
	{ "demand_metadata_misses", -1 },
	{ "prefetch_data_hits", -1 },
	{ "prefetch_metadata_hits", -1 },
	{ "prefetch_data_misses", -1 },
	{ "prefetch_metadata_misses", -1 },
	{ "size", -1 },
	{ "c", -1 },
	{ "mfu_hits", -1 },
	{ "mru_hits", -1 },
	{ "mru_ghost_hits", -1 },
	{ "mfu_ghost_hits", -1 },
	{ "evict_skip", -1 },
	{ "mutex_miss", -1 },
	{ "l2_hits", -1 },
	{ "l2_misses", -1 },
	{ "l2_size", -1 },
	{ "l2_asize", -1 },
	{ "l2_read_bytes", -1 },
	{ NULL },
};

static const char *cmd =
    "Usage: %s [-hvxf] [-f fields] [-o file] [-s string] [interval [count]]\n";

static const char *def_hdrs[] = {
	"time", "read", "miss", "miss%", "dmis", "dm%", "pmis", "pm%", "mmis",
	"mm%", "arcsz", "c", NULL
};

static const char *def_xhdrs[] = {
	"time", "mfu", "mru", "mfug", "mrug", "eskip", "mtxmis", "dread",
	"pread", "read", NULL
};

static char *outfile;
static char *sep = "  ";
static size_t count = 1;
static uint64_t interval = 1;
static size_t hdr_intr = 20;	/* Print header every 20 lines of output */
static colname_t *cols;
static size_t ncols;
static boolean_t raw;
static boolean_t hflag;

extern char *__progname;
char *cmdname;
int caught_cont;

static void detailed_usage(void);
static void usage(void);
static uint64_t convstr(const char *restrict);
static void hdr_to_fields(const char **);
static void set_output(const char *);
static colname_t field_to_num(const char *);
static void intr(int);
static void parse_fields(char *);
static boolean_t interested(kstat_t *);

static void calc(kstat_instance_t *, kstat_field_t *, uint64_t *);
static void print_header(void);
static void print_field(colname_t, uint64_t *, boolean_t);

void kstat_instances_update(kstat_ctl_t *, kstat_instance_t **,
    boolean_t (*)(kstat_t *));
void kstat_instances_read(kstat_ctl_t *, kstat_instance_t *, kstat_field_t *);

int
main(int argc, char * const *argv)
{
	kstat_ctl_t *kcp;
	kstat_instance_t *instances = NULL;
	struct itimerval itimer = { 0 };
	struct sigaction act;
	sigset_t set;
	uint64_t i = 0, count = 1;
	int c;
	int interval = 1;
	boolean_t forever = B_FALSE;

	cmdname = __progname;

	while ((c = getopt(argc, argv, "xo:hvs:f:r")) != -1) {
		switch (c) {
		case '?':
			(void) fprintf(stderr, _("Unknown option -%c\n"),
			    optopt);
			usage();
			break;
		case 'h':
			usage();
			break;
		case 'f':
			if (cols != NULL) {
				(void) fprintf(stderr,
				    _("-f and -x options are mutually "
				    "exclusive\n"));
				usage();
			}
			parse_fields(optarg);
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'r':
			raw = B_TRUE;
			break;
		case 's':
			sep = optarg;
			break;
		case 'v':
			detailed_usage();
			break;
		case 'x':
			if (cols != NULL) {
				(void) fprintf(stderr,
				    _("-f and -x options are mutually "
				    "exclusive\n"));
				usage();
			}
			hdr_to_fields(def_xhdrs);
			break;
		}
	}

	if (optind < argc) {
		uint64_t val = convstr(argv[optind]);

		if (val > INT32_MAX) {
			errx(EXIT_FAILURE, _("interval %llu is too large"),
			    val);
		}

		interval = val;
		optind++;
		forever = B_TRUE;
	}

	if (optind < argc) {
		count = convstr(argv[optind]);
		forever = B_FALSE;
		optind++;
	}

	if (cols == NULL)
		hdr_to_fields(def_hdrs);

	kcp = open_kstat();

	if (outfile != NULL)
		set_output(outfile);

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;
	(void) sigaction(SIGALRM, &act, NULL);

	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGALRM);
	(void) sigprocmask(SIG_BLOCK, &set, NULL);

	itimer.it_value.tv_sec = interval;
	itimer.it_interval.tv_sec = interval;

	if (setitimer(ITIMER_REAL, &itimer, NULL) != 0) {
		err(EXIT_FAILURE,
		    _("could not set timer to %d second%s"), interval,
		    interval == 1 ? "" : "s");
	}

	(void) sigemptyset(&set);

	while (i++ < count || forever) {
		uint64_t vals[NUM_VALS] = { 0 };

		kstat_instances_update(kcp, &instances, interested);
		kstat_instances_read(kcp, instances, ks_fields);
		calc(instances, ks_fields, vals);

		if ((i - 1) % 20 == 0)
			print_header();

		for (size_t j = 0; j < ncols; j++)
			print_field(cols[j], vals, !!((j + 1) == ncols));

		(void) sigsuspend(&set);
	}

	return (0);
}

static void
print_header(void)
{
	for (size_t i = 0; i < ncols; i++) {
		const char *hdr = col_defs[cols[i]].c_hdr;
		int len = col_defs[cols[i]].c_size;
		const char *s = (i + 1 < ncols) ? sep : "\n";

		/* Only pad if we're not displaying raw values */
		if (!raw)
			(void) printf("%*s%s", len, hdr, s);
		else
			(void) printf("%s%s", hdr, s);
	}
}

static void
print_field(colname_t c, uint64_t *v, boolean_t last)
{
	char str[21] = { 0 };		/* max length of uint64_t + NUL */

	if (c == CN_TIME) {
		if (raw) {
			(void) snprintf(str, sizeof (str), "%lld",
			    (long)v[CN_TIME]);
		} else {
			time_t now = v[CN_TIME];
			(void) strftime(str, sizeof (str) - 1, "%H:%M:%S",
			    localtime(&now));
		}
	} else {
		if (raw || col_defs[c].c_scale == 100) {
			(void) snprintf(str, sizeof (str), "%llu", v[c]);
		} else {
			uint32_t flags = 0;

			if (col_defs[c].c_scale == 1000)
				flags = NN_DIVISOR_1000;
			nicenum_scale(v[c], 1, str, sizeof (str), flags);
		}
	}

	(void) printf("%*s%s", (int)col_defs[c].c_size, str, last ? "\n" : sep);
}

static uint64_t
val(kstat_instance_t *ksi, ks_fieldname_t field)
{
	int gen = ksi->ksi_gen;
	return (ksi->ksi_data[gen ^ 1][field]);
}

static uint64_t
rate(kstat_instance_t *ksi, size_t n, ...)
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
calc(kstat_instance_t *ksi, kstat_field_t *ksf, uint64_t *v)
{
	v[CN_TIME] = (uint64_t)time(NULL);
	v[CN_HITS] = rate(ksi, 1, KSF_HITS);
	v[CN_MISS] = rate(ksi, 1, KSF_MISSES);
	v[CN_READ] = rate(ksi, 2, KSF_HITS, KSF_MISSES);
	v[CN_HITPCT] = v[CN_READ] > 0 ? 100 * v[CN_HITS] / v[CN_READ] : 0;
	v[CN_MISSPCT] = v[CN_READ] > 0 ? 100 - v[CN_HITPCT] : 0;

	v[CN_DHIT] = rate(ksi, 2, KSF_DEMAND_DATA_HITS,
	    KSF_DEMAND_METADATA_HITS);
	v[CN_DMIS] = rate(ksi, 2, KSF_DEMAND_DATA_MISSES,
	    KSF_DEMAND_METADATA_MISSES);
	v[CN_DREAD]= rate(ksi, 4, KSF_DEMAND_DATA_HITS,
	    KSF_DEMAND_METADATA_HITS, KSF_DEMAND_DATA_MISSES,
	    KSF_DEMAND_METADATA_MISSES);
	v[CN_DHITPCT] = v[CN_DREAD] > 0 ? (100 * v[CN_DHIT]) / v[CN_DREAD] : 0;
	v[CN_DMISPCT] = v[CN_DREAD] > 0 ? 100 - v[CN_DHITPCT] : 0;

	v[CN_PHIT] = rate(ksi, 2, KSF_PREFETCH_DATA_HITS,
	    KSF_PREFETCH_METADATA_HITS);
	v[CN_PMIS] = rate(ksi, 2, KSF_PREFETCH_DATA_MISSES,
	    KSF_PREFETCH_METADATA_MISSES);
	v[CN_PREAD] = rate(ksi, 4, KSF_PREFETCH_DATA_HITS,
	    KSF_PREFETCH_METADATA_HITS, KSF_PREFETCH_DATA_MISSES,
	    KSF_PREFETCH_METADATA_MISSES);
	v[CN_PHITPCT] = v[CN_PREAD] > 0 ? 100 * v[CN_PHIT] / v[CN_PREAD] : 0;
	v[CN_PMISPCT] = v[CN_PREAD] > 0 ? 100 - v[CN_PMISPCT] : 0;

	v[CN_MHIT] = rate(ksi, 2, KSF_PREFETCH_METADATA_HITS,
	    KSF_DEMAND_METADATA_HITS);
	v[CN_MMIS] = rate(ksi, 2, KSF_PREFETCH_METADATA_MISSES,
	    KSF_DEMAND_METADATA_MISSES);
	v[CN_MREAD] = rate(ksi, 4, KSF_PREFETCH_METADATA_HITS,
	    KSF_DEMAND_METADATA_HITS, KSF_PREFETCH_METADATA_MISSES,
	    KSF_DEMAND_METADATA_MISSES);

	v[CN_MHITPCT] = (v[CN_MREAD] > 0) ? 100 * v[CN_MHIT] / v[CN_MREAD] : 0;
	v[CN_MMISPCT] = (v[CN_MREAD] > 0) ? 100 - v[CN_MHITPCT] : 0;

	v[CN_ARCSZ] = val(ksi, KSF_SIZE);
	v[CN_C] = val(ksi, KSF_C);
	v[CN_MFU] = rate(ksi, 1, KSF_MFU_HITS);
	v[CN_MRU] = rate(ksi, 1, KSF_MRU_HITS);
	v[CN_MFUG] = rate(ksi, 1, KSF_MFU_GHOST_HITS);
	v[CN_MRUG] = rate(ksi, 1, KSF_MRU_GHOST_HITS);
	v[CN_ESKIP] = rate(ksi, 1, KSF_EVICT_SKIP);
	v[CN_MTXMIS] = rate(ksi, 1, KSF_MUTEX_MISS);
	v[CN_L2HITS] = rate(ksi, 1, KSF_L2_HITS);
	v[CN_L2MISS] = rate(ksi, 1, KSF_L2_MISSES);
	v[CN_L2READ] = rate(ksi, 2, KSF_L2_HITS, KSF_L2_MISSES);
	v[CN_L2HITPCT] = v[CN_L2READ] > 0 ?
	    100 * v[CN_L2HITS] / v[CN_L2READ] : 0;
	v[CN_L2MISSPCT] = v[CN_L2READ] > 0 ? 100 - v[CN_L2HITPCT] : 0;
	v[CN_L2ASIZE] = val(ksi, KSF_L2_ASIZE);
	v[CN_L2SIZE] = val(ksi, KSF_L2_SIZE);
	v[CN_L2BYTES] = rate(ksi, 1, KSF_L2_READ_BYTES);
}

static void
parse_fields(char *fstr)
{
	char *v = NULL;
	size_t cnt = 0;
	size_t ninvalid = 0;

	for (v = fstr, cnt = 0; *v != '\0'; v++) {
		if (*v == ',' || *v == ' ')
			cnt++;
	}
	cnt += 2; 	/* 1 first first field, 1 for terminating NULL */

	/* The largest either fields or invalid can be is cnt */
	char *invalid[cnt];

	if ((cols = calloc(cnt, sizeof (int))) == NULL)
		err(EXIT_FAILURE, _("Out of memory"));

	for (v = strtok(fstr, ", "); v != NULL; v = strtok(NULL, ", ")) {
		int fnum = field_to_num(v);

		if (fnum >= 0)
			cols[ncols++] = fnum;
		else
			invalid[ninvalid++] = v;
	}

	if (ninvalid > 0) {
		(void) fprintf(stderr, _("Invalid column definition! -- "));

		for (size_t i = 0; i < ninvalid; i++) {
			(void) fprintf(stderr, "%s%s", invalid[i],
			    (i + 1 == ninvalid) ? "\n\n" : ", ");
		}
		usage();
	}
}

static void
hdr_to_fields(const char **hdrs)
{
	for (const char **p = hdrs; *p != NULL; p++)
		ncols++;

	if ((cols = calloc(ncols + 1, sizeof (int))) == NULL)
		err(EXIT_FAILURE, _("Out of memory"));

	for (size_t i = 0; i < ncols; i++)
		cols[i] = field_to_num(hdrs[i]);

}

static int
kstat_field_hint(kstat_t *ksp, kstat_field_t *field)
{
	kstat_named_t *nm = KSTAT_NAMED_PTR(ksp);
	int i;

	VERIFY3S(ksp->ks_type, ==, KSTAT_TYPE_NAMED);

	for (i = 0; i < ksp->ks_ndata; i++) {
		if (strcmp(field->ksf_name, nm[i].name) == 0)
			return (field->ksf_hint = i);
	}

	errx(EXIT_FAILURE, _("could not find field '%s' in %s:%d\n"),
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

void
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
		err(EXIT_FAILURE, _("failed to update kstat chain"));

	for (ksi = *head; ksi != NULL; ksi = ksi->ksi_next)
		ksi->ksi_ksp = NULL;

	for (ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		kstat_instance_t *last = NULL;

		if (!interested(ksp))
			continue;

		/*
		 * Now look to see if we hae this instance and name.  (Yes,
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

		if ((ksi = malloc(sizeof (kstat_instance_t))) == NULL) {
			err(EXIT_FAILURE,
			    _("could not allocate memory for stat instance"));
		}

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
		ksi->ksi_next = i < ninstances - 1 ? sorted[i + 1]  : NULL;
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
				 * by displayed) and drive on.
				 */
				ksi->ksi_ksp = NULL;
				continue;
			}

			err(EXIT_FAILURE, _("failed to read kstat %s:%d"),
			    ksi->ksi_name, ksi->ksi_instance);
		}

		if (ksp->ks_type != KSTAT_TYPE_NAMED) {
			errx(EXIT_FAILURE, _("%s:%d is not a named kstat"),
			    ksi->ksi_name, ksi->ksi_instance);
		}

		if (ksi->ksi_data[0] == NULL) {
			size_t size = nfields * 2;
			uint64_t *data;

			if ((data = calloc(size, sizeof (uint64_t))) == NULL) {
				err(EXIT_FAILURE,
				    _("could not allocate memory for kstat "
				    "data"));
			}

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
set_output(const char *filename)
{
	int fd = open(filename, O_RDWR|O_CREAT);

	if (fd == -1)
		err(EXIT_FAILURE, _("Cannot open %s"), filename);

	if (dup2(fd, STDOUT_FILENO) == -1)
		err(EXIT_FAILURE, _("dup2 of stdout failed"));

	(void) close(fd);
}

static void
usage(void)
{
	(void) fprintf(stderr, _(cmd), __progname);
	(void) fprintf(stderr, _("\t -h : Print this help message\n"));
	(void) fprintf(stderr, _("\t -v : List all possible field headers "
	    "and definitions\n"));
	(void) fprintf(stderr, _("\t -x : Print extended stats\n"));
	(void) fprintf(stderr, _("\t -r : Raw output mode (values not "
	    "scaled)\n"));
	(void) fprintf(stderr, _("\t -f : Specify specific fields to print "
	    "(see -v)\n"));
	(void) fprintf(stderr, _("\t -o : Redirect output to the specified "
	    "file\n"));
	(void) fprintf(stderr, _("\t -s : Override default field separator "
	    "with custom character or string\n"));
	(void) fprintf(stderr, _("\nExamples:\n"));
	(void) fprintf(stderr, _("\tarcstat -o /tmp/a.log 2 10\n"));
	(void) fprintf(stderr, _("\tarcstat -s \",\" -o /tmp/a.log 2 10\n"));
	(void) fprintf(stderr, _("\tarcstat -v\n"));
	(void) fprintf(stderr, _("\tarcstat -f time,hit%%,dh%%,ph%%,mh%% 1\n"));
	exit(EXIT_FAILURE);
}

static void
detailed_usage(void)
{
	(void) fprintf(stderr, _(cmd), __progname);
	(void) fprintf(stderr, _("Field definitions are as follows:\n"));
	for (size_t i = 0; i < NUM_VALS; i++) {
		(void) fprintf(stderr, "%11s : %s\n", col_defs[i].c_hdr,
		    col_defs[i].c_desc);
	}
	exit(EXIT_FAILURE);
}

static colname_t
field_to_num(const char *field)
{
	for (colname_t i = 0; i < NUM_VALS; i++) {
		if (strcmp(field, col_defs[i].c_hdr) == 0)
			return (i);
	}
	return (-1);
}

static boolean_t
interested(kstat_t *ksp)
{
	const char *module = "zfs";
	const int instance = 0;
	const char *name = "arcstats";

	if (ksp->ks_instance != instance)
		return (B_FALSE);
	if (strcmp(ksp->ks_module, module) != 0)
		return (B_FALSE);
	if (strcmp(ksp->ks_name, name) != 0)
		return (B_FALSE);
	return (B_TRUE);
}

static uint64_t
convstr(const char *restrict s)
{
	uint64_t val = 0;

	errno = 0;
	val = strtoull(s, NULL, 10);
	if (errno != 0 && val == 0)
		err(EXIT_FAILURE, _("Could not parse to a number: '%s'"), s);

	return (val);
}

static void
intr(int sig)
{}
