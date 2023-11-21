/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Kyle Evans <kevans@FreeBSD.org>
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

#include <sys/param.h>

#include "stand.h"

static uint32_t loader_features;

#define	FEATURE_ENTRY(name, desc)	{ FEATURE_##name, #name, desc }
static const struct feature_entry {
	uint32_t	value;
	const char	*name;
	const char	*desc;
} feature_map[] = {
	FEATURE_ENTRY(EARLY_ACPI,  "Loader probes ACPI in early startup"),
};

void
feature_enable(uint32_t mask)
{

	loader_features |= mask;
}

bool
feature_name_is_enabled(const char *name)
{
	const struct feature_entry *entry;

	for (size_t i = 0; i < nitems(feature_map); i++) {
		entry = &feature_map[i];

		if (strcmp(entry->name, name) == 0)
			return ((loader_features & entry->value) != 0);
	}

	return (false);
}

void
feature_iter(feature_iter_fn *iter_fn, void *cookie)
{
	const struct feature_entry *entry;

	for (size_t i = 0; i < nitems(feature_map); i++) {
		entry = &feature_map[i];

		(*iter_fn)(cookie, entry->name, entry->desc,
		    (loader_features & entry->value) != 0);
	}
}
