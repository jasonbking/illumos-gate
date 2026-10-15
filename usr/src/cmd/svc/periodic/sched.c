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
 * Copyright 2026 Jason King
 */

#include <sys/debug.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "periodic.h"

/*
 * Scheduling of periodic services.
 *
 * Each periodic service has a base time (ps_base), when its next regular
 * run is due, and the time it will actually next run (ps_next_run), which
 * is normally the base time plus a random amount of up to jitter. Regular
 * runs happen at whole multiples of period after the first run (plus
 * jitter), so the base time advances by whole periods.
 *
 * When a service comes online, its first run depends on why:
 *
 * - When it is first enabled, or it restarts (e.g. svcadm restart, or
 *   disable then enable), it first runs after delay plus jitter.
 *
 * - After an outage (the system or zone rebooted since its schedule was
 *   last saved):
 *   - not persistent: as when first enabled.
 *   - persistent, recover false: the saved next_run, plus zero or more
 *     whole periods to bring it into the future.
 *   - persistent, recover true: as for recover false, except that if
 *     that skipped any runs, it runs once immediately, then continues on
 *     the pre-outage schedule.
 *
 * - When svc.periodicd restarts (or the service is refreshed) while the
 *   service is online: last_run plus period, plus zero or more whole
 *   periods to bring it into the future. If it has never run, its saved
 *   next_run (likewise brought into the future) is used.
 *
 * Stored times are checked when loaded to be between 0 and RUN_TIME_MAX,
 * and period and delay to be at most PERIODIC_TIME_MAX, so none of the
 * arithmetic here can overflow.
 */

/*
 * A random amount of time in [0, jitter].
 */
static int64_t
periodic_jitter(const periodic_data_t *p)
{
	if (p->ps_jitter == 0) {
		return (0);
	}
	if (p->ps_jitter == UINT32_MAX) {
		return ((int64_t)arc4random());
	}
	return ((int64_t)arc4random_uniform(p->ps_jitter + 1));
}

/*
 * Advance t by zero or more whole periods until it is in the future (after
 * now).
 */
static int64_t
advance(int64_t t, int64_t period, int64_t now)
{
	VERIFY3S(t, >=, 0);
	VERIFY3S(period, >, 0);

	if (t > now) {
		return (t);
	}
	return (t + ((now - t) / period + 1) * period);
}

/*
 * Start p's schedule afresh: the first run is after delay plus jitter.
 */
static void
periodic_start_new(periodic_data_t *p, int64_t now)
{
	p->ps_base = now + (int64_t)p->ps_delay;
	p->ps_next_run = p->ps_base + periodic_jitter(p);
}

static void
periodic_first_run(periodic_data_t *p, bool recover, bool outage,
    periodic_start_t how, int64_t now)
{
	int64_t period = (int64_t)p->ps_period;

	switch (how) {
	case PSTART_RESUME:
		if (p->ps_last_run != 0) {
			p->ps_base = advance(p->ps_last_run + period, period,
			    now);
			p->ps_next_run = p->ps_base;
		} else if (p->ps_next_run != 0) {
			p->ps_base = advance(p->ps_next_run, period, now);
			p->ps_next_run = p->ps_base;
		} else {
			periodic_start_new(p, now);
		}
		return;

	case PSTART_ONLINE:
		/*
		 * If its schedule was saved during this boot, it was enabled
		 * or restarted rather than coming back from an outage.
		 */
		if (!p->ps_persistent || p->ps_next_run == 0 || !outage) {
			periodic_start_new(p, now);
			return;
		}

		/* An outage: continue the pre-outage schedule */
		p->ps_base = advance(p->ps_next_run, period, now);
		if (recover && p->ps_next_run <= now) {
			/* Runs were missed; run now, then resume at ps_base */
			p->ps_next_run = now;
		} else {
			p->ps_next_run = p->ps_base;
		}
		return;
	}

	panic("Invalid periodic start %d", how);
}

/*
 * Work out p's next run after it has run.
 */
static void
periodic_after_run(periodic_data_t *p, int64_t now)
{
	int64_t period = (int64_t)p->ps_period;

	if (p->ps_next_run < p->ps_base) {
		/*
		 * That was a recovery run after an outage; resume the
		 * pre-outage schedule.
		 */
		p->ps_base = advance(p->ps_base, period, now);
		p->ps_next_run = p->ps_base;
		return;
	}

	p->ps_base = advance(p->ps_base + period, period, now);
	p->ps_next_run = p->ps_base + periodic_jitter(p);
}

/*
 * Scheduled services.
 *
 * A schedule's constraints are grouped into levels, from largest to
 * smallest: year; month or week_of_year; day or day_of_month (with
 * weekday_of_month); hour; minute. Its interval is the unit of a period (a
 * calendar year, month, ISO week (starting Monday), day, hour, or minute in
 * the schedule's timezone), and it runs at most once per period:
 *
 * - With a frequency of 1, every period is a candidate, and all of the
 *   constraints select which times qualify (e.g. an interval of day with
 *   month January runs on each day of January).
 *
 * - With a frequency of n > 1, the constraints from year down to the
 *   interval's level (all required; see sched_check_levels() in smf.c)
 *   select the first period (the anchor), and it runs in every nth period
 *   from there. The constraints below the interval's level select times
 *   within each of those periods.
 *
 * In each period it runs in, the run happens within a window: the first
 * stretch of the period, at the granularity of the finest constraint that
 * selects times within it (or the whole period if there is none), that
 * qualifies. E.g. an interval of day with hour 3 has a window of 03:00 to
 * 04:00 each day; an interval of month with day Tuesday has the first
 * Tuesday of each month.
 *
 * The first run is at a random time within the first window that hasn't
 * ended. Every later run is at the same offset into its window, without
 * further randomness. After an outage the saved next_run is used, moved
 * forward the same way if it has passed; with recover, a run that was
 * missed is made immediately, then the original schedule continues.
 */

const sched_unit_info_t sched_units[SU_NUM] = {
	[SU_MINUTE] =	{ "minute",	SL_MINUTE },
	[SU_HOUR] =	{ "hour",	SL_HOUR },
	[SU_DAY] =	{ "day",	SL_DAY },
	[SU_WEEK] =	{ "week",	SL_MONTH },
	[SU_MONTH] =	{ "month",	SL_MONTH },
	[SU_YEAR] =	{ "year",	SL_YEAR },
};

#define	SFIELD(name, level, unit, member, qual)	\
	{ name, level, unit, offsetof(scheduled_data_t, member), qual }

const sched_field_info_t sched_fields[SF_NUM] = {
	[SF_YEAR] =	SFIELD("year", SL_YEAR, SU_YEAR, ss_year, false),
	[SF_MONTH] =	SFIELD("month", SL_MONTH, SU_MONTH, ss_month, false),
	[SF_WEEK] =	SFIELD("week_of_year", SL_MONTH, SU_WEEK,
	    ss_week_of_year, false),
	[SF_MDAY] =	SFIELD("day_of_month", SL_DAY, SU_DAY,
	    ss_day_of_month, false),
	[SF_WDAY] =	SFIELD("day", SL_DAY, SU_DAY, ss_day, false),
	[SF_WOM] =	SFIELD("weekday_of_month", SL_DAY, SU_DAY,
	    ss_weekday_of_month, true),
	[SF_HOUR] =	SFIELD("hour", SL_HOUR, SU_HOUR, ss_hour, false),
	[SF_MINUTE] =	SFIELD("minute", SL_MINUTE, SU_MINUTE, ss_minute,
	    false),
};

/* The value of calendar field f of s */
int64_t *
sched_field(scheduled_data_t *s, sched_field_t f)
{
	return ((int64_t *)((uintptr_t)s + sched_fields[f].sf_offset));
}

/* Which calendar fields of s are set, as SF_BIT()s */
uint_t
sched_fields_set(const scheduled_data_t *s)
{
	uint_t set = 0;

	for (uint_t f = 0; f < SF_NUM; f++) {
		if (*sched_field((scheduled_data_t *)s, f) != SCHED_IVAL_NONE) {
			set |= SF_BIT(f);
		}
	}
	return (set);
}

/*
 * How far ahead we look for a time that matches a schedule (the start of the
 * year after SCHED_YEAR_MAX, in UTC), and the most steps we take doing so.
 * A schedule that can never match (e.g. day_of_month 31 in February) gives
 * up after SCHED_MAX_STEPS.
 */
#define	SCHED_TIME_END		((time_t)253402300800LL)
#define	SCHED_MAX_STEPS		100000

typedef struct sinfo {
	sched_unit_t	si_period;	/* unit of each period (the interval) */
	int64_t	si_n;		/* periods between runs */
	bool	si_anchored;	/* frequency > 1 */
	time_t	si_anchor;	/* if anchored, the first period */
	uint_t	si_match;	/* fields that select times in a period */
	sched_unit_t	si_window;	/* unit of each window */
} sinfo_t;

typedef enum wres {
	W_FOUND,	/* the period has a window */
	W_NONE,		/* the period has no window */
	W_NEVER,	/* no period ever will */
} wres_t;

/*
 * Do the calculations for s in its timezone. As illumos cron does
 * (next_time()), we temporarily set TZ. tz_lock is held while it is set, so
 * that anything else converting times (e.g. logmsg()) uses the right
 * timezone. Nothing between tz_enter() and tz_exit() may call logmsg().
 */
static char	saved_tz[MAXPATHLEN];
static bool	had_tz;

static void
tz_enter(const scheduled_data_t *s)
{
	const char *tz;

	if (s->ss_timezone == NULL) {
		return;
	}

	mutex_enter(&tz_lock);
	tz = getenv("TZ");
	had_tz = (tz != NULL);
	if (had_tz) {
		(void) strlcpy(saved_tz, tz, sizeof (saved_tz));
	}
	VERIFY0(setenv("TZ", s->ss_timezone, 1));
	tzset();
}

static void
tz_exit(const scheduled_data_t *s)
{
	if (s->ss_timezone == NULL) {
		return;
	}

	if (had_tz) {
		VERIFY0(setenv("TZ", saved_tz, 1));
	} else {
		VERIFY0(unsetenv("TZ"));
	}
	tzset();
	mutex_exit(&tz_lock);
}

static time_t
mk(struct tm *tm)
{
	tm->tm_isdst = -1;
	return (mktime(tm));
}

/*
 * The start of the unit u containing t. Minutes and hours are found by
 * arithmetic rather than mktime(), so that when the clock falls back, an hour
 * that occurs twice is two distinct hours rather than being resolved to one
 * of them.
 */
static time_t
unit_start(time_t t, sched_unit_t u)
{
	struct tm tm;

	(void) localtime_r(&t, &tm);
	switch (u) {
	case SU_MINUTE:
		return (t - tm.tm_sec);
	case SU_HOUR:
		return (t - tm.tm_min * 60 - tm.tm_sec);
	default:
		break;
	}

	switch (u) {
	case SU_YEAR:
		tm.tm_mon = 0;
		/* FALLTHROUGH */
	case SU_MONTH:
		tm.tm_mday = 1;
		/* FALLTHROUGH */
	case SU_DAY:
		tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
		break;
	case SU_WEEK:
		/* ISO weeks start on Monday */
		tm.tm_mday -= (tm.tm_wday + 6) % 7;
		tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
		break;
	default:
		break;
	}
	return (mk(&tm));
}

/*
 * Add n units u to t (the start of a unit). Minutes and hours are added as
 * seconds, so a daylight saving change doesn't stall or skip them.
 */
static time_t
unit_add(time_t t, sched_unit_t u, int64_t n)
{
	struct tm tm;

	switch (u) {
	case SU_MINUTE:
		return (t + n * 60);
	case SU_HOUR:
		return (t + n * 60 * 60);
	default:
		break;
	}

	(void) localtime_r(&t, &tm);
	switch (u) {
	case SU_DAY:
		tm.tm_mday += (int)n;
		break;
	case SU_WEEK:
		tm.tm_mday += (int)(n * 7);
		break;
	case SU_MONTH:
		tm.tm_mon += (int)n;
		break;
	case SU_YEAR:
		tm.tm_year += (int)n;
		break;
	default:
		break;
	}
	return (mk(&tm));
}

/*
 * The start of the unit u after the one containing t. This always moves
 * forward, even if a daylight saving change makes the calendar ambiguous.
 */
static time_t
next_unit(time_t t, sched_unit_t u)
{
	time_t n = unit_add(unit_start(t, u), u, 1);

	return ((n > t) ? n : t + 60);
}

static bool
is_leap(int y)
{
	return ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0);
}

static int
days_in_month(int y, int mon)
{
	static const int dim[] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};

	return ((mon == 1 && is_leap(y)) ? 29 : dim[mon]);
}

/* The day of the week (0 is Sunday) of 1 January of year y */
static int
jan1_wday(int y)
{
	int p = y - 1;

	return ((1 + 5 * (p % 4) + 4 * (p % 100) + 6 * (p % 400)) % 7);
}

/* The number of ISO 8601 weeks in ISO year y */
static int
iso_weeks(int y)
{
	int w = jan1_wday(y);

	return ((w == 4 || (w == 3 && is_leap(y))) ? 53 : 52);
}

/* The ISO 8601 week number of tm, and its ISO year */
static int
iso_week(const struct tm *tm, int *yearp)
{
	int y = tm->tm_year + 1900;
	/* The day of the year of this week's Thursday */
	int thu = tm->tm_yday - (tm->tm_wday + 6) % 7 + 3;

	if (thu < 0) {
		y--;
		thu += is_leap(y) ? 366 : 365;
	} else if (thu >= (is_leap(y) ? 366 : 365)) {
		thu -= is_leap(y) ? 366 : 365;
		y++;
	}

	*yearp = y;
	return (thu / 7 + 1);
}

/*
 * Whether each field of s matches tm. Negative values count back from the
 * end (of the year, month, week, day, or hour).
 */
static bool
match_month(const scheduled_data_t *s, const struct tm *tm)
{
	int64_t m = s->ss_month;

	return (tm->tm_mon + 1 == ((m > 0) ? m : 13 + m));
}

static bool
match_week(const scheduled_data_t *s, const struct tm *tm)
{
	int64_t	w = s->ss_week_of_year;
	int	y;
	int	wk = iso_week(tm, &y);

	return (wk == ((w > 0) ? w : iso_weeks(y) + w + 1));
}

static bool
match_mday(const scheduled_data_t *s, const struct tm *tm)
{
	int64_t	d = s->ss_day_of_month;
	int	dim = days_in_month(tm->tm_year + 1900, tm->tm_mon);

	return (tm->tm_mday == ((d > 0) ? d : dim + d + 1));
}

static bool
match_wday(const scheduled_data_t *s, const struct tm *tm)
{
	/* day 1 is Sunday (tm_wday 0); -1 is Saturday, the end of the week */
	int64_t	d = s->ss_day;
	int64_t	k = s->ss_weekday_of_month;
	int	dim = days_in_month(tm->tm_year + 1900, tm->tm_mon);

	if (tm->tm_wday != ((d > 0) ? d - 1 : 7 + d)) {
		return (false);
	}
	if (k == SCHED_IVAL_NONE) {
		return (true);
	}
	if (k > 0) {
		return ((tm->tm_mday - 1) / 7 + 1 == k);
	}
	return ((dim - tm->tm_mday) / 7 + 1 == -k);
}

static int
sched_hour(const scheduled_data_t *s)
{
	int64_t h = s->ss_hour;

	return ((int)((h >= 0) ? h : 24 + h));
}

static int
sched_minute(const scheduled_data_t *s)
{
	int64_t m = s->ss_minute;

	return ((int)((m >= 0) ? m : 60 + m));
}

/* Minutes since midnight of tm's wall clock time */
static int
wall_min(const struct tm *tm)
{
	return (tm->tm_hour * 60 + tm->tm_min);
}

/*
 * Whether stepping from tm to ntm (the next hour or minute) jumped over the
 * wall clock time target (minutes since midnight) on the same day, i.e. the
 * clock sprang forward over it.
 */
static bool
skipped(const struct tm *tm, const struct tm *ntm, int target)
{
	return (ntm->tm_mday == tm->tm_mday && wall_min(tm) < target &&
	    wall_min(ntm) > target);
}

/*
 * Find the first time in [c, end) matching the given fields of s, where c is
 * the start of a unit at least as fine as each of those fields.
 *
 * If the clock springs forward over the requested hour (and minute) on a
 * day that otherwise matches, the first time after the change stands in for
 * all of the skipped time: it is the match, and *gapp is set. E.g. with hour
 * 2 and minute 30, when the clock goes from 02:00 to 03:00 the match is
 * 03:00. When the clock falls back, the first occurrence of a repeated time
 * matches.
 */
static bool
next_match(const scheduled_data_t *s, uint_t fields, time_t c, time_t end,
    time_t *mp, bool *gapp)
{
	struct tm	tm, ntm;
	time_t		n;
	bool		use_hour = (fields & SF_BIT(SF_HOUR)) != 0;
	bool		use_min = (fields & SF_BIT(SF_MINUTE)) != 0;

	*gapp = false;

	for (uint_t i = 0; i < SCHED_MAX_STEPS; i++) {
		if (c >= end) {
			return (false);
		}
		(void) localtime_r(&c, &tm);

		if ((fields & SF_BIT(SF_YEAR)) != 0) {
			int64_t y = tm.tm_year + 1900;

			if (y > s->ss_year) {
				return (false);
			}
			if (y < s->ss_year) {
				struct tm jan1 = { 0 };

				jan1.tm_year = (int)(s->ss_year - 1900);
				jan1.tm_mday = 1;
				c = mk(&jan1);
				continue;
			}
		}
		if ((fields & SF_BIT(SF_MONTH)) != 0 && !match_month(s, &tm)) {
			c = next_unit(c, SU_MONTH);
			continue;
		}
		if ((fields & SF_BIT(SF_WEEK)) != 0 && !match_week(s, &tm)) {
			c = next_unit(c, SU_WEEK);
			continue;
		}
		if (((fields & SF_BIT(SF_MDAY)) != 0 && !match_mday(s, &tm)) ||
		    ((fields & SF_BIT(SF_WDAY)) != 0 && !match_wday(s, &tm))) {
			c = next_unit(c, SU_DAY);
			continue;
		}
		if (use_hour && tm.tm_hour != sched_hour(s)) {
			int target = sched_hour(s) * 60 +
			    (use_min ? sched_minute(s) : 0);

			n = next_unit(c, SU_HOUR);
			(void) localtime_r(&n, &ntm);
			if (skipped(&tm, &ntm, target)) {
				*mp = n;
				*gapp = true;
				return (true);
			}
			c = n;
			continue;
		}
		if (use_min && tm.tm_min != sched_minute(s)) {
			int target = tm.tm_hour * 60 + sched_minute(s);

			n = next_unit(c, SU_MINUTE);
			(void) localtime_r(&n, &ntm);
			if (skipped(&tm, &ntm, target)) {
				*mp = n;
				*gapp = true;
				return (true);
			}
			c = n;
			continue;
		}

		*mp = c;
		return (true);
	}

	return (false);
}

/*
 * Work out how s is scheduled. Fails if s has a frequency > 1 but its anchor
 * never occurs.
 */
static bool
sched_info(const scheduled_data_t *s, sinfo_t *si)
{
	uint_t		set = sched_fields_set(s);
	uint_t		anchor = 0;
	sched_level_t	level = sched_units[s->ss_interval].su_level;

	si->si_period = s->ss_interval;
	si->si_anchored = (s->ss_frequency > 1);
	si->si_n = si->si_anchored ? (int64_t)s->ss_frequency : 1;
	si->si_anchor = 0;
	si->si_match = set;

	if (si->si_anchored) {
		for (uint_t f = 0; f < SF_NUM; f++) {
			if (sched_fields[f].sf_level <= level) {
				anchor |= set & SF_BIT(f);
			}
		}
		si->si_match = set & ~anchor;
	}

	si->si_window = si->si_period;
	for (uint_t f = 0; f < SF_NUM; f++) {
		if ((si->si_match & SF_BIT(f)) != 0 &&
		    sched_fields[f].sf_unit < si->si_window) {
			si->si_window = sched_fields[f].sf_unit;
		}
	}

	if (si->si_anchored) {
		struct tm	jan1 = { 0 };
		time_t		m;
		bool		gap;

		/* year is required with a frequency > 1 */
		VERIFY3S(s->ss_year, !=, SCHED_IVAL_NONE);
		jan1.tm_year = (int)(s->ss_year - 1900);
		jan1.tm_mday = 1;
		if (!next_match(s, anchor, mk(&jan1), SCHED_TIME_END, &m,
		    &gap)) {
			return (false);
		}
		si->si_anchor = unit_start(m, si->si_period);
	}

	return (true);
}

/*
 * Find the window of the period starting at p. For an unanchored schedule,
 * periods without a window are skipped, so this is the first window in or
 * after p's period. *nextp is set to the next period to look at.
 */
static wres_t
window_in(const scheduled_data_t *s, const sinfo_t *si, time_t p,
    time_t *wsp, time_t *wep, time_t *nextp)
{
	time_t	m, pstart, pend, ws;
	bool	gap;

	if (!si->si_anchored) {
		if (!next_match(s, si->si_match, p, SCHED_TIME_END, &m,
		    &gap)) {
			return (W_NEVER);
		}
		pstart = unit_start(m, si->si_period);
		pend = next_unit(pstart, si->si_period);
		*nextp = pend;
	} else {
		pstart = p;
		pend = next_unit(p, si->si_period);
		*nextp = unit_add(p, si->si_period, si->si_n);
		if (*nextp <= p) {
			return (W_NEVER);
		}
		if (!next_match(s, si->si_match, p, pend, &m, &gap)) {
			return (W_NONE);
		}
	}

	if (gap) {
		/*
		 * The window was skipped when the clock sprang forward; it
		 * becomes the single moment after the change.
		 */
		*wsp = m;
		*wep = m + 1;
		return (W_FOUND);
	}

	ws = unit_start(m, si->si_window);
	*wsp = MAX(ws, pstart);
	*wep = MIN(next_unit(ws, si->si_window), pend);
	return (W_FOUND);
}

/* An estimate of how many units u there are from a to t (t >= a) */
static int64_t
units_between(time_t a, time_t t, sched_unit_t u)
{
	struct tm ta, tt;

	switch (u) {
	case SU_MINUTE:
		return ((t - a) / 60);
	case SU_HOUR:
		return ((t - a) / (60 * 60));
	case SU_DAY:
		return ((t - a) / (24 * 60 * 60));
	case SU_WEEK:
		return ((t - a) / (7 * 24 * 60 * 60));
	default:
		break;
	}

	(void) localtime_r(&a, &ta);
	(void) localtime_r(&t, &tt);
	if (u == SU_YEAR) {
		return (tt.tm_year - ta.tm_year);
	}
	return ((tt.tm_year - ta.tm_year) * 12 + (tt.tm_mon - ta.tm_mon));
}

/* The start of the period containing t (or the anchor, if t is before it) */
static time_t
period_of(const sinfo_t *si, time_t t)
{
	int64_t	k;
	time_t	p, q;

	if (!si->si_anchored) {
		return (unit_start(t, si->si_period));
	}
	if (t <= si->si_anchor) {
		return (si->si_anchor);
	}

	/* Estimate, then correct for daylight saving and month lengths */
	k = units_between(si->si_anchor, t, si->si_period) / si->si_n;
	p = unit_add(si->si_anchor, si->si_period, k * si->si_n);
	while (k > 0 && p > t) {
		k--;
		p = unit_add(si->si_anchor, si->si_period, k * si->si_n);
	}
	for (;;) {
		q = unit_add(si->si_anchor, si->si_period, (k + 1) * si->si_n);
		if (q > t || q <= p) {
			break;
		}
		k++;
		p = q;
	}
	return (p);
}

/*
 * Find a run time after now, starting with the period at p. If offset is
 * negative, it's a random time within the first window that hasn't ended;
 * otherwise it's offset into the first window where that is after now. 0 if
 * there is none.
 */
static time_t
find_run(const scheduled_data_t *s, const sinfo_t *si, time_t p, time_t now,
    int64_t offset, int64_t *offsetp)
{
	for (uint_t i = 0; i < SCHED_MAX_STEPS; i++) {
		time_t ws, we, next, lo, t;

		switch (window_in(s, si, p, &ws, &we, &next)) {
		case W_NEVER:
			return (0);
		case W_FOUND:
			if (offset < 0) {
				if (we > now) {
					lo = MAX(ws, now);
					t = lo + (time_t)arc4random_uniform(
					    (uint32_t)(we - lo));
					*offsetp = t - ws;
					return (t);
				}
			} else {
				t = ws + MIN(offset, we - ws - 1);
				if (t > now) {
					return (t);
				}
			}
			break;
		case W_NONE:
			break;
		}
		p = next;
	}
	return (0);
}

/*
 * The first run of s: a random time in its first window that hasn't ended.
 * Its offset into the window is kept in ss_offset for later runs.
 */
static time_t
sched_first(scheduled_data_t *s, time_t now)
{
	sinfo_t si;

	if (!sched_info(s, &si)) {
		return (0);
	}
	return (find_run(s, &si, period_of(&si, now), now, -1, &s->ss_offset));
}

/*
 * The first run of s after now, at the same offset into its window as its
 * earlier runs. If that offset isn't known (e.g. after s was reloaded), it
 * is worked out from t, an earlier run time. A window that the clock sprang
 * forward over is only a moment long, so it can't give the offset.
 */
static time_t
sched_after(scheduled_data_t *s, time_t t, time_t now)
{
	sinfo_t	si;
	time_t	ws, we, next;
	int64_t	unused;

	if (!sched_info(s, &si)) {
		return (0);
	}
	if (s->ss_offset < 0) {
		s->ss_offset = 0;
		if (window_in(s, &si, period_of(&si, t), &ws, &we, &next) ==
		    W_FOUND && ws <= t && t < we && we - ws > 1) {
			s->ss_offset = t - ws;
		}
	}
	return (find_run(s, &si, period_of(&si, MAX(t, now)), now,
	    s->ss_offset, &unused));
}

/*
 * t if it's in the future, otherwise the first run after now on the same
 * schedule.
 */
static time_t
sched_advance(scheduled_data_t *s, time_t t, time_t now)
{
	return ((t > now) ? t : sched_after(s, t, now));
}

static void
scheduled_first_run(const char *fmri, scheduled_data_t *s, bool outage,
    periodic_start_t how, time_t now)
{
	tz_enter(s);

	if (s->ss_next_run == 0 ||
	    (how == PSTART_ONLINE && !outage)) {
		/* First enabled, or restarted: a fresh random time */
		s->ss_base = s->ss_next_run = sched_first(s, now);
	} else if (how == PSTART_RESUME) {
		/* We restarted: carry on with the saved schedule */
		s->ss_base = s->ss_next_run = sched_advance(s, s->ss_next_run,
		    now);
	} else {
		/* An outage: continue the pre-outage schedule */
		s->ss_base = sched_advance(s, s->ss_next_run, now);
		if (s->ss_recover && s->ss_next_run <= now) {
			/* A run was missed; run now, then resume */
			s->ss_next_run = now;
		} else {
			s->ss_next_run = s->ss_base;
		}
	}

	tz_exit(s);

	if (s->ss_next_run == 0) {
		logmsg(_("%s: schedule %s never runs"), fmri, s->ss_name);
	}
}

static void
scheduled_after_run(const char *fmri, scheduled_data_t *s, time_t now)
{
	/* Only the schedules that were due have run */
	if (s->ss_next_run == 0 || s->ss_next_run > now) {
		return;
	}

	tz_enter(s);
	if (s->ss_next_run < s->ss_base) {
		/* That was a recovery run; resume the regular schedule */
		s->ss_next_run = sched_advance(s, s->ss_base, now);
	} else {
		s->ss_next_run = sched_after(s, s->ss_next_run, now);
	}
	s->ss_base = s->ss_next_run;
	tz_exit(s);

	if (s->ss_next_run == 0) {
		logmsg(_("%s: schedule %s never runs again"), fmri,
		    s->ss_name);
	}
}

/*
 * Set svc's next run time when it comes online (PSTART_ONLINE), or when we
 * resume running an instance that's already online (PSTART_RESUME).
 */
void
svc_first_run(periodic_svc_t *svc, periodic_start_t how, int64_t now)
{
	/* Its run times were saved before the system (or zone) booted */
	bool outage = (svc->ps_saved_boot != boot_time);

	switch (svc->ps_type) {
	case PST_PERIODIC:
		VERIFY3P(svc->ps_u.psu_periodic, !=, NULL);
		periodic_first_run(svc->ps_u.psu_periodic,
		    svc->ps_exec.pe_recover, outage, how, now);
		return;
	case PST_SCHEDULED:
		for (scheduled_data_t *s = svc->ps_u.psu_scheduled; s != NULL;
		    s = s->ss_next) {
			scheduled_first_run(svc->ps_fmri, s, outage, how,
			    (time_t)now);
		}
		return;
	}

	panic("Invalid service type %d", svc->ps_type);
}

/*
 * Record that svc ran at now: its last_run, or for a scheduled service, the
 * last_run of each schedule that was due. Called just before svc_after_run()
 * when a run starts (not when one is skipped).
 */
void
svc_mark_run(periodic_svc_t *svc, int64_t now)
{
	switch (svc->ps_type) {
	case PST_PERIODIC:
		VERIFY3P(svc->ps_u.psu_periodic, !=, NULL);
		svc->ps_u.psu_periodic->ps_last_run = now;
		return;
	case PST_SCHEDULED:
		for (scheduled_data_t *s = svc->ps_u.psu_scheduled; s != NULL;
		    s = s->ss_next) {
			if (s->ss_next_run != 0 && s->ss_next_run <= now) {
				s->ss_last_run = now;
			}
		}
		return;
	}

	panic("Invalid service type %d", svc->ps_type);
}

/*
 * Set svc's next run time after it has run.
 */
void
svc_after_run(periodic_svc_t *svc, int64_t now)
{
	switch (svc->ps_type) {
	case PST_PERIODIC:
		VERIFY3P(svc->ps_u.psu_periodic, !=, NULL);
		periodic_after_run(svc->ps_u.psu_periodic, now);
		return;
	case PST_SCHEDULED:
		for (scheduled_data_t *s = svc->ps_u.psu_scheduled; s != NULL;
		    s = s->ss_next) {
			scheduled_after_run(svc->ps_fmri, s, (time_t)now);
		}
		return;
	}

	panic("Invalid service type %d", svc->ps_type);
}

/*
 * When svc next runs: for a scheduled service, the earliest of its
 * schedules. INT64_MAX if it has no next run.
 */
int64_t
svc_next_run(const periodic_svc_t *svc)
{
	const scheduled_data_t	*s;
	int64_t			next = INT64_MAX;

	switch (svc->ps_type) {
	case PST_PERIODIC:
		VERIFY3P(svc->ps_u.psu_periodic, !=, NULL);
		if (svc->ps_u.psu_periodic->ps_next_run != 0) {
			next = svc->ps_u.psu_periodic->ps_next_run;
		}
		return (next);
	case PST_SCHEDULED:
		for (s = svc->ps_u.psu_scheduled; s != NULL; s = s->ss_next) {
			if (s->ss_next_run != 0 && s->ss_next_run < next) {
				next = s->ss_next_run;
			}
		}
		return (next);
	}

	panic("Invalid service type %d", svc->ps_type);
}
