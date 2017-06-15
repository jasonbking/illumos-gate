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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/zone.h>
#include <sys/debug.h>
#include <alloca.h>
#include <stdio.h>
#include <getopt.h>
#include <kstat.h>
#include <math.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <libintl.h>
#include <zone.h>
#include <locale.h>
#include <signal.h>
#include "statcommon.h"

#define	_(x) gettext(x)

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

typedef struct zone_map {
	char		zm_zonename[ZONENAME_MAX];
	zoneid_t	zm_id;
} zone_map_t;

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

typedef enum field_e {
	F_READS,
	F_NREAD,
	F_RLENTIME,
	F_WAITTIME,
	F_RTIME,
} field_t;

/* These MUST appear in the same order as field_t */
static kstat_field_t ks_fields[] = {
	{ "reads", -1 },
	{ "nread", -1 },
	{ "rlentime", -1 },
	{ "waittime", -1 },
	{ "rtime", -1 },
	{ NULL, -1 },
};

extern char *__progname;
char *cmdname;
int caught_cont;

static zone_map_t *zone_map;
static size_t nzones;

static const char *bytes_prefix;
static const char *interval_suffix;
static const char *data_fmt;
static char *header;
static uint64_t bytes_divisor;
static uint64_t count;
static boolean_t use_mb;
static boolean_t use_comma;
static boolean_t use_interval;
static boolean_t hide_zeroes;
static boolean_t all_zones;

static void usage(const char *);
static boolean_t convstr(const char *restrict, uint64_t *restrict);
static void get_zones(zoneid_t);
static void print_stats(const zone_map_t *, kstat_instance_t *);
static void kstat_instances_update(kstat_ctl_t *, kstat_instance_t **,
    boolean_t (*)(kstat_t *));
static void kstat_instances_read(kstat_ctl_t *, kstat_instance_t *,
    kstat_field_t *);
static boolean_t interested(kstat_t *);
static uint64_t fval_delta(kstat_instance_t *, field_t);
static uint64_t snaptime(kstat_instance_t *);

int
main(int argc, char * const *argv)
{
	kstat_ctl_t *kcp = NULL;
	kstat_instance_t *instances = NULL;
	hrtime_t start, interval;
	size_t i = 0, rows_printed = 0;
	int forever, c;

	cmdname = __progname;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "hIMrzZ")) != -1) {
		switch (c) {
		case 'M':
			use_mb = B_TRUE;
			break;
		case 'I':
			use_interval = B_TRUE;
			break;
		case 'r':
			use_comma = B_TRUE;
			break;
		case 'z':
			hide_zeroes = B_TRUE;
			break;
		case 'Z':
			all_zones = B_TRUE;
			break;
		default:
			usage(argv[0]);
		}
	}

	interval = 0;
	forever = 0;
	count = 1;

	if (optind < argc) {
		uint64_t ival = 0;

		if (!convstr(argv[optind], &ival) || ival == 0 ||
		    ival > INT64_MAX)
			usage(argv[0]);

		forever = 1;
		count = UINT64_MAX;
		interval = ival * NANOSEC;
	}
	optind++;

	if (optind < argc) {
		if (!convstr(argv[optind], &count))
			usage(argv[0]);
		forever = 0;
	}
	optind++;

	if (optind < argc)
		usage(argv[0]);

	bytes_prefix = (use_mb) ? "M" : "k";
	bytes_divisor = (use_mb) ? 1024 * 1024 : 1024;
	interval_suffix = (use_interval) ? "i" : "s";

	get_zones(all_zones ? ALL_ZONES : getzoneid());

	if (asprintf(&header, use_comma ?
	    "r/%s,%sr/%s,actv,wsvc_t,asvc_t,%%b,zone\n" :
	    "    r/%s   %sr/%s   actv wsvc_t asvc_t  %%b zone\n",
	    interval_suffix, bytes_prefix, interval_suffix) == -1)
		err(EXIT_FAILURE, _("Out of memory"));

	data_fmt = use_comma ?
	    "%.1f,%.1f,%.1f,%.1f,%.1f,%d,%.8s,%d\n" :
	    " %6.1f %6.1f %6.1f %6.1f %6.1f %3d %.8s (%d)\n";

	if ((kcp = kstat_open()) == NULL)
		err(EXIT_FAILURE, _("Could not open /dev/kstat"));

	if (count > 1) {
		/* Set up signal handler for SIGCONT */
		if (signal(SIGCONT, cont_handler) == SIG_ERR)
			fail(1, _("could not setup signal handler"));
	}

	start = gethrtime();

	while (forever || i++ <= count) {
		kstat_instances_update(kcp, &instances, interested);
		kstat_instances_read(kcp, instances, ks_fields);

		if (rows_printed == 0 || all_zones)
			(void) printf("%s", header);

		for (size_t j = 0; j < nzones; j++) {
			/*
			 * zone_zfs instance numbers are the zone id, both
			 * lists are sorted by zone id, and w've filtered to
			 * only list the zones we know about at startup,
			 * so these should match.
			 */
			VERIFY3S(zone_map[j].zm_id, ==,
			    instances[j].ksi_instance);

			print_stats(&zone_map[j], &instances[j]);
		}

		rows_printed = (rows_printed + 1) % 20;
		sleep_until(&start, interval, forever, &caught_cont);
	}

	return (0);
}

static boolean_t
interested(kstat_t *ksp)
{
	const char *module = "zone_zfs";

	if (strcmp(ksp->ks_module, module) != 0)
		return (B_FALSE);

	for (size_t i = 0; i < nzones; i++) {
		if (ksp->ks_instance == zone_map[i].zm_id)
			return (B_TRUE);
	}

	return (B_FALSE);
}

static void
print_stats(const zone_map_t *restrict zm, kstat_instance_t *ksi)
{
	uint64_t tdelta = snaptime(ksi);
	double etime = (double)tdelta / NANOSEC;
	double rate_divisor = (use_interval) ? 1.0 : etime;

	/* Overall transactions per second */
	uint64_t ops = fval_delta(ksi, F_READS);
	double tps = (double)ops / etime;

	/* Basic statistics */
	double reads = (double)ops / rate_divisor;
	double nread = (double)fval_delta(ksi, F_NREAD) / rate_divisor /
	    bytes_divisor;

	/* Average length of disk run queue */
	double actv = (double)fval_delta(ksi, F_RLENTIME) / tdelta;

	/* Average disk wait and service time */
	double wsvc = (ops > 0) ? ((double)fval_delta(ksi, F_WAITTIME) /
	    MICROSEC) / ops : 0.0;
	double asvc = (tps > 0.0) ? actv * (1000 / tps) : 0.0;

	/* % time the disk run queue is active */
	uint64_t b_pct = fval_delta(ksi, F_RTIME) * 100 / tdelta;

	/*
	 * Since we only display one decimal point of precision, any
	 * |value| < 0.1 will show as zero, so we treat it as such for
	 * display purposes.
	 */
	if (!hide_zeroes || fabs(reads) > 0.09 || fabs(nread) > 0.09) {
		/*LINTED*/
		(void) printf(data_fmt, reads, nread, actv, wsvc, asvc,
		    (int)b_pct, zm->zm_zonename, zm->zm_id);
	}
}

static uint64_t
snaptime(kstat_instance_t *ksi)
{
	hrtime_t old;
	int gen = ksi->ksi_gen;

	if (ksi->ksi_snaptime[gen] != 0)
		old = ksi->ksi_snaptime[gen];
	else
		old = ksi->ksi_ksp->ks_crtime;

	return (hrtime_delta(old, ksi->ksi_snaptime[gen ^ 1]));
}

static uint64_t
fval_delta(kstat_instance_t *ksi, field_t field)
{
	int gen = ksi->ksi_gen;
	return (ksi->ksi_data[gen ^ 1][field] - ksi->ksi_data[gen][field]);
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
		err(EXIT_FAILURE, _("failed to update kstat chain"));

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
		ksi->ksi_next = i < ninstances - 1 ? sorted[i + 1] : NULL;
	}
}

static void
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

			err(EXIT_FAILURE, _("failed to read kstat %s:%d"),
			    ksi->ksi_name, ksi->ksi_instance);
		}

		if (ksp->ks_type != KSTAT_TYPE_NAMED) {
			errx(EXIT_FAILURE, _("%s:%d is not a named kstat"),
			    ksi->ksi_name, ksi->ksi_instance);
		}

		if (ksi->ksi_data[0] == NULL) {
			size_t size = nfields * sizeof (uint64_t) * 2;
			uint64_t *data;

			if ((data = malloc(size)) == NULL) {
				err(EXIT_FAILURE,
				    _("could not allocate memory for kstat "
				    "data"));
			}

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

static int
zone_map_compare(const void *lhs, const void *rhs)
{
	const zone_map_t *l = lhs;
	const zone_map_t *r = rhs;

	if (l->zm_id < r->zm_id)
		return (-1);
	else if (l->zm_id > r->zm_id)
		return (1);
	else
		return (0);
}

static void
get_zones(zoneid_t zid)
{
	if (zid != ALL_ZONES) {
		nzones = 1;
		zone_map = calloc(1, sizeof (zone_map_t));
		zone_map[0].zm_id = zid;
		if (getzonenamebyid(zid, zone_map[0].zm_zonename,
		    ZONENAME_MAX) < 0)
			err(EXIT_FAILURE, _("cannot get zone name"));
		return;
	}

	uint_t n = 0, n1 = 0;
	zoneid_t *zids = NULL;

	VERIFY0(zone_list(NULL, &n));

	do {
		n1 = n;
		free(zids);
		zids = calloc(n, sizeof (zoneid_t));
		VERIFY0(zone_list(zids, &n));
	} while (n1 != n);

	if ((zone_map = calloc(n, sizeof (zone_map_t))) == NULL)
		err(EXIT_FAILURE, _("cannot allocate memory for zone map"));

	for (size_t i = 0; i < n; i++) {
		/*
		 * This may fail if a zone has shutdown between the call
		 * to zone_list() and getzonenamebyid.  If that happens,
		 * we just ignore that zone.
		 */
		if (getzonenamebyid(zids[i], zone_map[nzones].zm_zonename,
		    ZONENAME_MAX) < 0)
			continue;

		zone_map[nzones++].zm_id = zids[i];
	}
	free(zids);

	qsort(zone_map, nzones, sizeof (zone_map_t), zone_map_compare);
}

static boolean_t
convstr(const char *restrict s, uint64_t *restrict valp)
{
	errno = 0;
	*valp = strtoull(s, NULL, 10);
	if (errno != 0 && *valp == 0) {
		err(EXIT_FAILURE, "strtotull '%s'", s);
		return (B_FALSE);
	}
	return (B_TRUE);
}

static void
usage(const char *prog)
{
	(void) fprintf(stderr,
	    _("USAGE: %s [-hIMrzZ] [interval [count]]\n"), prog);
	(void) fprintf(stderr,
	    _("   eg, ziostat		# print summary since zone boot\n"));
	(void) fprintf(stderr,
	    _("       ziostat 1		# print continually every 1 second\n"));
	(void) fprintf(stderr,
	    _("       ziostat 1 15	# print 5 times, every 1 second\n"));
	(void) fprintf(stderr,
	    _("       ziostat -I	# print results per interval (where "
	    "applicable)\n"));
	(void) fprintf(stderr,
	    _("       ziostat -M	# print results in MB/s\n"));
	(void) fprintf(stderr,
	    _("       ziostat -r	# print results in comma-separated "
	    "format\n"));
	(void) fprintf(stderr,
	    _("       ziostat -z	# hide zones with no ZFS I/O "
	    "activity\n"));
	(void) fprintf(stderr,
	    _("       ziostat -Z	# print results for all zones\n"));

	exit(EXIT_FAILURE);
}
