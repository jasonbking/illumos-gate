/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "statcommon.h"

#include <poll.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

/*
 * The time we delay before retrying after an allocation
 * failure, in milliseconds
 */
#define RETRY_DELAY 200

extern char *cmdname;
extern int caught_cont;

/*PRINTFLIKE2*/
void
fail(int do_perror, char *message, ...)
{
	va_list args;
	int save_errno = errno;

	va_start(args, message);
	(void) fprintf(stderr, "%s: ", cmdname);
	(void) vfprintf(stderr, message, args);
	va_end(args);
	if (do_perror)
		(void) fprintf(stderr, ": %s", strerror(save_errno));
	(void) fprintf(stderr, "\n");
	exit(2);
}

/*
 * Sleep until *wakeup + interval, keeping cadence where desired
 *
 * *wakeup -	The time we last wanted to wake up. Updated.
 * interval -	We want to sleep until *wakeup + interval
 * forever -	Running for infinite periods, so cadence not important
 * *caught_cont - Global set by signal handler if we got a SIGCONT
 */
void
sleep_until(hrtime_t *wakeup, hrtime_t interval, int forever,
    int *caught_cont)
{
	hrtime_t now, pause, pause_left;
	struct timespec pause_tv;
	int status;

	now = gethrtime();
	pause = *wakeup + interval - now;

	if (pause <= 0 || pause < (interval / 4))
		if (forever || *caught_cont) {
			/* Reset our cadence (see comment below) */
			*wakeup = now + interval;
			pause = interval;
		} else {
			/*
			 * If we got here, then the time between the
			 * output we just did, and the scheduled time
			 * for the next output is < 1/4 of our requested
			 * interval AND the number of intervals has been
			 * requested AND we have never caught a SIGCONT
			 * (so we have never been suspended).  In this
			 * case, we'll try to stay to the desired
			 * cadence, and we will pause for 1/2 the normal
			 * interval this time.
			 */
			pause = interval / 2;
			*wakeup += interval;
		}
	else
		*wakeup += interval;
	if (pause < 1000)
		/* Near enough */
		return;

	/* Now do the actual sleep */
	pause_left = pause;
	do {
		pause_tv.tv_sec = pause_left / NANOSEC;
		pause_tv.tv_nsec = pause_left % NANOSEC;
		status = nanosleep(&pause_tv, (struct timespec *)NULL);
		if (status < 0) {
			if (errno == EINTR) {
				now = gethrtime();
				pause_left = *wakeup - now;
				if (pause_left < 1000)
					/* Near enough */
					return;
			} else {
				fail(1, "nanosleep failed");
			}
		}
	} while (status != 0);
}

/*
 * Signal handler - so we can be aware of SIGCONT
 */
void
cont_handler(int sig_number)
{
	/* Re-set the signal handler */
	(void) signal(sig_number, cont_handler);
	caught_cont = 1;
}

kstat_ctl_t *
open_kstat(void)
{
	kstat_ctl_t *kc;

	while ((kc = kstat_open()) == NULL) {
		if (errno == EAGAIN)
			(void) poll(NULL, 0, RETRY_DELAY);
		else
			fail(1, "kstat_open failed");
	}

	return (kc);
}

uint64_t
kstat_delta(kstat_t *old, kstat_t *new, char *name)
{
	kstat_named_t *knew = kstat_data_lookup(new, name);
	if (old && old->ks_data) {
		kstat_named_t *kold = kstat_data_lookup(old, name);
		return (knew->value.ui64 - kold->value.ui64);
	}
	return (knew->value.ui64);
}

int
kstat_copy(const kstat_t *src, kstat_t *dst)
{
	*dst = *src;

	if (src->ks_data != NULL) {
		if ((dst->ks_data = malloc(src->ks_data_size)) == NULL)
			return (-1);
		(void) memcpy(dst->ks_data, src->ks_data, src->ks_data_size);
	} else {
		dst->ks_data = NULL;
		dst->ks_data_size = 0;
	}
	return (0);
}

/*
 * Return the number of ticks delta between two hrtime_t
 * values. Attempt to cater for various kinds of overflow
 * in hrtime_t - no matter how improbable.
 */
uint64_t
hrtime_delta(hrtime_t old, hrtime_t new)
{
	uint64_t del;

	if ((new >= old) && (old >= 0L))
		return (new - old);
	else {
		/*
		 * We've overflowed the positive portion of an
		 * hrtime_t.
		 */
		if (new < 0L) {
			/*
			 * The new value is negative. Handle the
			 * case where the old value is positive or
			 * negative.
			 */
			uint64_t n1;
			uint64_t o1;

			n1 = -new;
			if (old > 0L)
				return (n1 - old);
			else {
				o1 = -old;
				del = n1 - o1;
				return (del);
			}
		} else {
			/*
			 * Either we've just gone from being negative
			 * to positive *or* the last entry was positive
			 * and the new entry is also positive but *less*
			 * than the old entry. This implies we waited
			 * quite a few days on a very fast system between
			 * iostat displays.
			 */
			if (old < 0L) {
				uint64_t o2;

				o2 = -old;
				del = UINT64_MAX - o2;
			} else {
				del = UINT64_MAX - old;
			}
			del += new;
			return (del);
		}
	}
}
