/*-
 * Copyright (c) 2024 Kyle Evans <kevans@FreeBSD.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/cdefs.h>
#include "namespace.h"
#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include "un-namespace.h"

#include "thr_private.h"

__weak_reference(_pthread_foreach_np, pthread_foreach_np);

int
_pthread_foreach_np(pthread_foreach_np_routine_t routine, void *cookie)
{
	struct pthread_foreach_np_data data;
	struct pthread *curthread = _get_curthread();
	pthread_t thread;
	int ret;

	data.version = PTHREAD_FOREACH_NP_DATA_VERSION;

	ret = 0;

	THREAD_LIST_RDLOCK(curthread);
	TAILQ_FOREACH(thread, &_thread_list, tle) {
		if (thread->state == PS_DEAD)
			continue;

		data.thread = thread;
		data.lwpid = TID(thread);
		ret = routine(cookie, &data);
		if (ret != 0)
			break;
	}
	THREAD_LIST_UNLOCK(curthread);

	return (ret);
}
