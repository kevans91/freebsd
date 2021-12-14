/*-
 * Copyright (c) 2021 Kyle Evans <kevans@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <atf-c.h>

static bool chrooted;

typedef void (*checker_fn)(struct tm *);
static void check_for_cst(struct tm *);
static void check_for_utc(struct tm *);

static const struct tzcheck {
	const char *tz;
	checker_fn checker;
	int delay;
} tzcheck[] = {
	{
		.tz = "UTC",
		.checker = &check_for_utc,
	},
	{
		.tz = "CST6CDT",
		.checker = &check_for_utc,
		/* Implementation detail: not enough delay to re-check. */
	},
	{
		.tz = "CST6CDT",
		/* Will be ignored if we don't detect timezone changes. */
		.checker = &check_for_cst,
#ifdef DETECT_TZ_CHANGES
		/*
		 * Implementation detail: tzcode will recheck every 61 seconds.
		 *
		 * Don't bother with the delay for stock builds so that we don't
		 * add the latency in the common case.  Folks that want to test
		 * tz change detection need to opt-in with the usual build
		 * option.
		 */
		.delay = 61,
#endif
	},
};

static void
check_for_cst(struct tm *tmp)
{

	ATF_REQUIRE_STREQ(tmp->tm_isdst ? "CDT" : "CST", tmp->tm_zone);
	/* -6 offset, -5 in CDT.  Can't really validate DST. */
	ATF_REQUIRE_EQ(-(60 * 60 * 6) + (tmp->tm_isdst ? (60 * 60) : 0),
	    tmp->tm_gmtoff);
}

static void
check_for_utc(struct tm *tmp)
{

	ATF_REQUIRE_STREQ("UTC", tmp->tm_zone);
	ATF_REQUIRE_EQ(0, tmp->tm_gmtoff);
}

static void
copy_files(const char *path, const char *dest)
{
	pid_t p;
	int status;

	p = fork();
	ATF_REQUIRE(p != -1);

	if (p == 0) {
		execlp("cp", "cp", "-R", path, dest, NULL);
		_exit(1);
	}

	waitpid(p, &status, 0);
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
}

static void
setup_chroot(void)
{

	ATF_REQUIRE_EQ(0, mkdir("etc", 0755));
	ATF_REQUIRE_EQ(0, mkdir("usr", 0755));
	ATF_REQUIRE_EQ(0, mkdir("usr/share", 0755));

	/* Less string manipulation... */
	copy_files("/usr/share/zoneinfo", "usr/share/zoneinfo");

	ATF_REQUIRE_EQ(0, chroot("."));
	chrooted = true;
}

static void
setup_tz(const char *tz)
{
	char *tzfile, *tzpath;
	struct stat sb;
	int len;

	if (!chrooted) {
		setup_chroot();

		/*
		 * This dance ensures that we start using /etc/localtime from
		 * the chroot and ignoring any TZ that may have been set in the
		 * environment.
		 */
		setenv("TZ", "", 1);
		tzset();
		unsetenv("TZ");
	}
	tzfile = tzpath = NULL;
	len = asprintf(&tzfile, "/usr/share/zoneinfo/%s", tz);
	ATF_REQUIRE(len > 0);
	if (stat(tzfile, &sb) == -1) {
		ATF_REQUIRE(errno == ENOENT);
		free(tzfile);
		atf_tc_skip("needed timezone '%s' not installed", tz);
	}

	unlink("/etc/localtime");
	ATF_REQUIRE_EQ(0, symlink(tzfile, "/etc/localtime"));
	free(tzfile);
	tzset();
}

ATF_TC_WITHOUT_HEAD(tmdata_cst);
ATF_TC_BODY(tmdata_cst, tc)
{
	time_t clk;
	struct tm tm;

	clk = 0;
	memset(&tm, '\0', sizeof(tm));

	setup_tz("CST6CDT");
	ATF_REQUIRE_EQ(&tm, localtime_r(&clk, &tm));
	check_for_cst(&tm);
}

ATF_TC_WITHOUT_HEAD(tmdata_utc);
ATF_TC_BODY(tmdata_utc, tc)
{
	time_t clk;
	struct tm tm;

	clk = 0;
	memset(&tm, '\0', sizeof(tm));

	setup_tz("UTC");
	ATF_REQUIRE_EQ(&tm, localtime_r(&clk, &tm));
	check_for_utc(&tm);
}

ATF_TC_WITHOUT_HEAD(tzchange);
ATF_TC_BODY(tzchange, tc)
{
	const struct tzcheck *tzc;
	time_t clk;
	struct tm tm;

	clk = 0;

	setup_tz("UTC");
	for (size_t i = 0; i < nitems(tzcheck); i++) {
		tzc = &tzcheck[i];
		memset(&tm, '\0', sizeof(tm));

		setup_tz(tzc->tz);
		sleep(tzc->delay);
		ATF_REQUIRE_EQ(&tm, localtime_r(&clk, &tm));

#ifdef DETECT_TZ_CHANGES
		(*tzc->checker)(&tm);
#else
		check_for_utc(&tm);
#endif
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, tmdata_cst);
	ATF_TP_ADD_TC(tp, tmdata_utc);
	ATF_TP_ADD_TC(tp, tzchange);

	return (atf_no_error());
}
