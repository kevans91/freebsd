/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2020 Kyle Evans <kevans@FreeBSD.org>
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include <atf-c.h>

struct testparams {
	int		 tp_nexpected;
	pthread_cond_t	*tp_cvp;
	const int	*tp_expected;
	pthread_mutex_t	*tp_mtxp;
	int		*tp_sflags;
	int		 tp_idx;
};

#define	TP_POPULATE(tp, expected)			\
	do {						\
		(tp).tp_idx = 0;			\
		(tp).tp_expected = (expected);		\
		(tp).tp_nexpected = nitems(expected);	\
	} while (0);

static int
trivialcb(void *data, int fd)
{
	struct testparams *tpp;

	tpp = data;

	ATF_REQUIRE_EQ(tpp->tp_expected[tpp->tp_idx++], fd);
	return (0);
}

ATF_TC_WITHOUT_HEAD(trivial_test);
ATF_TC_BODY(trivial_test, tc)
{
	struct testparams tp;
	const int expected[] = { 0, 1, 2 };

	TP_POPULATE(tp, expected);

	ATF_REQUIRE_EQ(0, fdwalk(trivialcb, &tp));
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);
}

static int
earlycb(void *data, int fd)
{
	struct testparams *tpp;

	/* Trigger early termination at the last one. */
	if (fd == 2)
		return (fd);

	tpp = data;
	ATF_REQUIRE_EQ(tpp->tp_expected[tpp->tp_idx++], fd);

	return (0);
}

ATF_TC_WITHOUT_HEAD(early_term_test);
ATF_TC_BODY(early_term_test, tc)
{
	struct testparams tp;
	const int expected[] = { 0, 1 };

	TP_POPULATE(tp, expected);

	ATF_REQUIRE_EQ(2, fdwalk(earlycb, &tp));
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);
}

ATF_TC_WITHOUT_HEAD(gap_test);
ATF_TC_BODY(gap_test, tc)
{
	struct testparams tp;
	const int expected[] = { 0, 1, 2, 4, 5 };
	const int expected2[] = { 0, 1, 2 };
	int fd1, fd2, fd3;

	TP_POPULATE(tp, expected);

	fd1 = open("/", O_RDONLY);
	fd2 = dup(fd1);
	fd3 = dup(fd1);
	close(fd1);

	ATF_REQUIRE_EQ(4, fd2);
	ATF_REQUIRE_EQ(5, fd3);

	fdwalk(trivialcb, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);
	close(fd2);
	close(fd3);

	TP_POPULATE(tp, expected2);
	fdwalk(trivialcb, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);
}

/*
 * This is a little bit of a silly test, but let's do it anyways.  This simply
 * tests that we don't become arbitrarily restricted by rlimits.  Even if a
 * process has opened a bunch of files then dropped the limit below some of the
 * higher descriptor numbers that are opened.
 */
ATF_TC_WITHOUT_HEAD(rlim_test);
ATF_TC_BODY(rlim_test, tc)
{
	struct testparams tp;
	const int expected[] = { 0, 1, 2, 45, 46, 47, 48, 49 };
	const int expected2[] = { 0, 1, 2 };
	struct rlimit rl;
	int iter;

	for (iter = 3; iter < 50; ++iter) {
		ATF_REQUIRE_EQ(iter, open("/", O_RDONLY));
	}

	for (iter = 3; iter < 45; ++iter) {
		close(iter);
	}

	ATF_REQUIRE_EQ(0, getrlimit(RLIMIT_NOFILE, &rl));
	rl.rlim_cur = rl.rlim_max = 25;
	ATF_REQUIRE_EQ(0, setrlimit(RLIMIT_NOFILE, &rl));

	TP_POPULATE(tp, expected);
	fdwalk(trivialcb, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);

	for (iter = 45; iter < 50; ++iter) {
		close(iter);
	}

	TP_POPULATE(tp, expected2);

	/*
	 * A final check that we've closed all the extra descriptors so that
	 * we're in a consistent state for any subsequent tests.
	 */
	fdwalk(trivialcb, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);
}

struct syncdata {
	pthread_cond_t	*cvp;
	pthread_mutex_t	*mtxp;
	int		*sflags;
};

#define	SFLAG_OPEN	0x01
#define	SFLAG_WALK	0x02

#define	FD_DEFER_MAX	6

static void *
concur_opener(void *data)
{
	struct syncdata *sd;
	int fd;

	sd = data;
	pthread_mutex_lock(sd->mtxp);
	while ((*sd->sflags & SFLAG_OPEN) == 0)
		pthread_cond_wait(sd->cvp, sd->mtxp);

	/* Wake up and open some fds */
	*sd->sflags |= SFLAG_WALK;
	for (fd = 3; fd <= FD_DEFER_MAX; ++fd) {
		ATF_REQUIRE_EQ(fd, open("/", O_RDONLY));
	}

	pthread_mutex_unlock(sd->mtxp);
	pthread_cond_signal(sd->cvp);

	return (NULL);
}

static int
concur_walker(void *data, int fd)
{
	struct testparams *tpp;

	tpp = data;
	if (fd == 0) {
		/*
		 * Pause for a minute; wake up the opener and let it open some
		 * fds before we proceed.  This thread should never see any fd
		 * higher than 2.  We're going to take the lock, signal the
		 * other thread, then wait on a signal from the other thread to
		 * continue.
		 */
		pthread_mutex_lock(tpp->tp_mtxp);
		*tpp->tp_sflags |= SFLAG_OPEN;
		pthread_cond_signal(tpp->tp_cvp);

		while ((*tpp->tp_sflags & SFLAG_WALK) == 0)
			pthread_cond_wait(tpp->tp_cvp, tpp->tp_mtxp);

		pthread_mutex_unlock(tpp->tp_mtxp);

		ATF_REQUIRE(fcntl(FD_DEFER_MAX, F_GETFD) != -1);
	}

	ATF_REQUIRE_EQ(tpp->tp_expected[tpp->tp_idx++], fd);
	return (0);
}

ATF_TC_WITHOUT_HEAD(concur_test);
ATF_TC_BODY(concur_test, tc)
{
	struct testparams tp;
	struct syncdata sd;
	pthread_t thr;
	static pthread_cond_t cv;
	static pthread_mutex_t mtx;
	const int expected[] = { 0, 1, 2 };
	const int expected2[] = { 0, 1, 2, 3, 4, 5, 6 /* FD_DEFER_MAX */ };
	int error, fd, sflags;

	ATF_REQUIRE_EQ(FD_DEFER_MAX, expected2[nitems(expected2) - 1]);

	sflags = 0;
	pthread_mutex_init(&mtx, NULL);
	pthread_cond_init(&cv, NULL);
	sd.cvp = &cv;
	sd.mtxp = &mtx;
	sd.sflags = &sflags;

	error = pthread_create(&thr, NULL, concur_opener, &sd);
	ATF_REQUIRE_EQ(0, error);

	TP_POPULATE(tp, expected);
	tp.tp_cvp = &cv;
	tp.tp_mtxp = &mtx;
	tp.tp_sflags = &sflags;

	fdwalk(concur_walker, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);

	TP_POPULATE(tp, expected2);
	fdwalk(trivialcb, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);

	for (fd = 3; fd <= FD_DEFER_MAX; ++fd)
		close(fd);

	pthread_join(thr, NULL);
	pthread_cond_destroy(&cv);
	pthread_mutex_destroy(&mtx);
}

static int
same_thr_walker(void *data, int fd)
{
	struct testparams *tpp;

	tpp = data;
	if (fd == 0) {
		/*
		 * First invocation: open up more fds.  These should not
		 * influence the fds that we end up walking.
		 */
		for (int nfd = 3; nfd <= FD_DEFER_MAX; ++nfd)
			ATF_REQUIRE_EQ(nfd, open("/", O_RDONLY));
	}

	ATF_REQUIRE_EQ(tpp->tp_expected[tpp->tp_idx++], fd);
	return (0);
}

ATF_TC_WITHOUT_HEAD(same_thr_test);
ATF_TC_BODY(same_thr_test, tc)
{
	struct testparams tp;
	const int expected[] = { 0, 1, 2 };
	const int expected2[] = { 0, 1, 2, 3, 4, 5, 6 /* FD_DEFER_MAX */ };
	int fd;

	ATF_REQUIRE_EQ(FD_DEFER_MAX, expected2[nitems(expected2) - 1]);

	TP_POPULATE(tp, expected);

	fdwalk(same_thr_walker, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);

	TP_POPULATE(tp, expected2);
	fdwalk(trivialcb, &tp);
	ATF_REQUIRE_EQ(tp.tp_nexpected, tp.tp_idx);

	for (fd = 3; fd <= FD_DEFER_MAX; ++fd)
		close(fd);
}

#define	EXIT_OK			0
#define	EXIT_CB_INVOKED		1
#define	EXIT_RETURNFAIL		2

static int
empty_walker(void *data, int fd)
{

	exit(EXIT_CB_INVOKED);
}

ATF_TC_WITHOUT_HEAD(empty_test);
ATF_TC_BODY(empty_test, tc)
{
	pid_t pid;

	pid = fork();
	ATF_REQUIRE(pid != -1);
	/* Close all in the child, fdwalk(). */
	if (pid == 0) {
		int error;

		closefrom(0);
		error = fdwalk(empty_walker, NULL);
		if (error != 0)
			exit(EXIT_RETURNFAIL);
		exit(EXIT_OK);
	} else {
		int status;

		waitpid(pid, &status, 0);
		ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
	}
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, trivial_test);
	ATF_TP_ADD_TC(tp, early_term_test);
	ATF_TP_ADD_TC(tp, gap_test);
	ATF_TP_ADD_TC(tp, rlim_test);
	ATF_TP_ADD_TC(tp, concur_test);
	ATF_TP_ADD_TC(tp, same_thr_test);
	ATF_TP_ADD_TC(tp, empty_test);

	return (atf_no_error());
}
