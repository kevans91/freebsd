/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Kyle Evans <kevans@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>

#include <stdbool.h>
#include <string.h>

#include <be.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define	BE_METATABLE	"boot environment iterator metatable"

int luaopen_be(lua_State *);

static libbe_handle_t *lbh;
static const char *be_valid_props[] = {
	"dataset",
	"name",
	"mounted",
	"mountpoint",
	"origin",
	"creation",
	"active",
	"used",
	"usedds",
	"usedsnap",
	"referenced",
	"nextboot",
};

enum be_valtype_t {
	VT_UNKNOWN,
	VT_BOOL,
	VT_INT,
	VT_STR,
};

#define	L_REQUIRES_LIBBE(L)	do {	\
	if (lbh == NULL) {		\
		lua_pushnil(L);		\
		return (1);		\
	}				\
} while(0)

#define	L_ERRORRET_LIBBE(L, error)	do {				\
	if ((error) != 0) {						\
		lua_pushnil(L);						\
		lua_pushstring((L), libbe_error_description(lbh));	\
		return (2);						\
	}								\
} while(0)

struct l_be_iter {
	nvpair_t	*cur;
	nvlist_t	*props;
};

static enum be_valtype_t
be_proptype(const char *propname)
{

	if (strcmp(propname, "active") == 0 ||
	    strcmp(propname, "nextboot") == 0 ||
	    strcmp(propname, "bootonce") == 0)
		return (VT_BOOL);
	if (strcmp(propname, "mounted") == 0 ||
	    strcmp(propname, "dataset") == 0 ||
	    strcmp(propname, "name") == 0 ||
	    strcmp(propname, "origin") == 0)
		return (VT_STR);
	if (strcmp(propname, "used") == 0 ||
	    strcmp(propname, "usedds") == 0 ||
	    strcmp(propname, "usedsnap") == 0 ||
	    strcmp(propname, "creation") == 0)
		return (VT_INT);
	return (VT_UNKNOWN);
}

static int
l_be_iter_next(lua_State *L)
{
	struct l_be_iter *iter, **iterp;
	char *strval;
	nvlist_t *dsprops;
	int nparams, ptable;
	boolean_t boolval;

	ptable = lua_upvalueindex(1);
	nparams = lua_rawlen(L, ptable);

	iterp = (struct l_be_iter **)luaL_checkudata(L, 1, BE_METATABLE);
	iter = *iterp;
	luaL_argcheck(L, iter != NULL, 1, "closed jail iterator");

	iter->cur = nvlist_next_nvpair(iter->props, iter->cur);
	if (iter->cur == NULL) {
		be_prop_list_free(iter->props);
		free(iter);
		*iterp = NULL;
		return (0);
	}

	nvpair_value_nvlist(iter->cur, &dsprops);

	/*
	 * Finally, we'll fill in the return table with whatever parameters the
	 * user requested.  The name is always returned.
	 */
	lua_newtable(L);
	nvlist_lookup_string(dsprops, "name", &strval);
	lua_pushstring(L, strval);
	lua_setfield(L, -2, "name");

	for (int i = 0; i < nparams; ++i) {
		const char *param;
		enum be_valtype_t ptype;

		lua_rawgeti(L, ptable, i + 1);
		param = lua_tostring(L, -1);

		if (strcmp(param, "name") == 0) {
			lua_pop(L, 1);
			continue;
		}

		switch (ptype = be_proptype(param)) {
		case VT_BOOL:
			if (nvlist_lookup_boolean_value(dsprops, param,
			    &boolval) != 0)
				break;
			lua_pushboolean(L, boolval);
			lua_setfield(L, -3, param);
			break;
		case VT_STR:
		case VT_INT:
			if (nvlist_lookup_string(dsprops, param,
			    &strval) != 0)
				break;
			if (ptype == VT_STR)
				lua_pushstring(L, strval);
			else
				lua_pushinteger(L, strtoull(strval, NULL, 10));
			lua_setfield(L, -3, param);
			break;
		default:
			break;
		}

		lua_pop(L, 1);
	}

	return (1);
}

static int
l_be_iter_close(lua_State *L)
{

	struct l_be_iter *iter, **iterp;

	/*
	 * Since we're using this as the __gc method as well, there's a good
	 * chance that it's already been cleaned up by iterating to the end of
	 * the list.
	 */
	iterp = (struct l_be_iter **)lua_touserdata(L, 1);
	iter = *iterp;
	if (iter == NULL)
		return (0);

	be_prop_list_free(iter->props);
	free(iter);
	*iterp = NULL;
	return (0);
}

static int
l_list(lua_State *L)
{
	struct l_be_iter *iter;
	int nargs;

	nargs = lua_gettop(L);
	if (nargs >= 1) {
		luaL_checktype(L, 1, LUA_TTABLE);
		if (nargs > 1)
			lua_settop(L, 1);
	} else {
		/* Push an empty param table into the closure.  Simple. */
		lua_newtable(L);
	}

	/* Validate parameter list. */
	for (size_t i = 0; i < lua_rawlen(L, 1); ++i) {
		const char *param;
		bool valid;

		lua_rawgeti(L, 1, i + 1);
		if (lua_type(L, -1) != LUA_TSTRING)
			luaL_argerror(L, 1, "param names must be strings");

		param = lua_tostring(L, -1);
		valid = false;
		for (size_t j = 0; j < nitems(be_valid_props); ++j) {
			if (strcmp(param, be_valid_props[j]) == 0) {
				valid = true;
				break;
			}
		}
		if (!valid)
			luaL_error(L, "specified invalid param name '%s'",
			    param);

		lua_pop(L, 1);
	}

	iter = malloc(sizeof(*iter));
	if (iter == NULL)
		return (luaL_error(L, "malloc: %s", strerror(errno)));

	iter->cur = NULL;
	if (be_prop_list_alloc(&iter->props) != 0) {
		free(iter);
		return (luaL_error(L, "be_prop_list_alloc failure"));
	}

	if (be_get_bootenv_props(lbh, iter->props) != 0) {
		be_prop_list_free(iter->props);
		free(iter);
		lua_pushnil(L);
		lua_pushstring(L, "BE fetch failure");
		return (2);
	}

	lua_pushcclosure(L, l_be_iter_next, 1);
	*(struct l_be_iter **)lua_newuserdata(L,
	    sizeof(struct l_be_iter **)) = iter;
	luaL_getmetatable(L, BE_METATABLE);
	lua_setmetatable(L, -2);
	return (2);
}

static void
register_be_metatable(lua_State *L)
{
	luaL_newmetatable(L, BE_METATABLE);
	lua_newtable(L);
	lua_pushcfunction(L, l_be_iter_next);
	lua_setfield(L, -2, "next");
	lua_pushcfunction(L, l_be_iter_close);
	lua_setfield(L, -2, "close");

	lua_setfield(L, -2, "__index");

	lua_pushcfunction(L, l_be_iter_close);
	lua_setfield(L, -2, "__gc");

	lua_pop(L, 1);
}

static int
l_switch(lua_State *L)
{
	libbe_handle_t *nhdl;
	const char *root;

	root = luaL_checkstring(L, 1);

	nhdl = libbe_init(root);
	if (nhdl == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "Failed to initialize new root");
		return (2);
	}

	if (lbh != NULL)
		libbe_close(lbh);
	lbh = nhdl;
	lua_pushboolean(L, 1);
	return (1);
}

static int
l_active(lua_State *L)
{

	L_REQUIRES_LIBBE(L);
	lua_pushstring(L, be_active_name(lbh));
	lua_pushstring(L, be_active_path(lbh));
	return (2);
}

static int
l_nextboot(lua_State *L)
{

	L_REQUIRES_LIBBE(L);
	lua_pushstring(L, be_nextboot_name(lbh));
	lua_pushstring(L, be_nextboot_path(lbh));
	return (2);
}

static int
l_root(lua_State *L)
{

	L_REQUIRES_LIBBE(L);
	lua_pushstring(L, be_root_path(lbh));
	return (1);
}

static int
l_create(lua_State *L)
{
	const char *name, *origin;
	int error, nargs;
	bool snap;

	L_REQUIRES_LIBBE(L);
	nargs = lua_gettop(L);
	luaL_argcheck(L, nargs > 0, 1, "not enough arguments");
	name = luaL_checkstring(L, 1);
	origin = NULL;
	if (nargs != 1) {
		origin = luaL_checkstring(L, 2);
		snap = strchr(origin, '@') != NULL;
	}

	if (origin == NULL)
		error = be_create(lbh, name);
	else if (snap)
		error = be_create_from_existing_snap(lbh, name, origin);
	else
		error = be_create_from_existing(lbh, name, origin);
	L_ERRORRET_LIBBE(L, error);
	lua_pushboolean(L, 1);
	return (1);
}

static int
l_snapshot(lua_State *L)
{
	const char *name, *snap;
	int error;

	L_REQUIRES_LIBBE(L);
	luaL_argcheck(L, lua_gettop(L) >= 2, 1, "not enough arguments");
	name = luaL_checkstring(L, 1);
	snap = luaL_checkstring(L, 2);

	error = be_snapshot(lbh, name, snap, true, NULL);
	L_ERRORRET_LIBBE(L, error);
	lua_pushboolean(L, 1);
	return (1);
}

static int
l_rename(lua_State *L)
{
	const char *name, *newName;
	int error;

	L_REQUIRES_LIBBE(L);
	luaL_argcheck(L, lua_gettop(L) >= 2, 1, "not enough arguments");
	name = luaL_checkstring(L, 1);
	newName = luaL_checkstring(L, 2);

	error = be_rename(lbh, name, newName);
	L_ERRORRET_LIBBE(L, error);
	lua_pushboolean(L, 1);
	return (1);
}

static int
l_activate(lua_State *L)
{
	const char *name;
	int error, nargs;
	bool temp;

	L_REQUIRES_LIBBE(L);
	nargs = lua_gettop(L);
	luaL_argcheck(L, nargs >= 1, 1, "not enough arguments");
	name = luaL_checkstring(L, 1);
	temp = false;
	if (nargs > 1)
		temp = lua_toboolean(L, 2);

	error = be_activate(lbh, name, temp);
	L_ERRORRET_LIBBE(L, error);
	lua_pushboolean(L, 1);
	return (1);
}

static int
l_deactivate(lua_State *L)
{
	const char *name;
	int error, nargs;
	bool temp;

	L_REQUIRES_LIBBE(L);
	nargs = lua_gettop(L);
	luaL_argcheck(L, nargs >= 1, 1, "not enough arguments");
	name = luaL_checkstring(L, 1);
	temp = false;
	if (nargs > 1)
		temp = lua_toboolean(L, 2);

	error = be_deactivate(lbh, name, temp);
	L_ERRORRET_LIBBE(L, error);
	lua_pushboolean(L, 1);
	return (1);
}

#define	BE_DESTROY_FLAGS	\
	(BE_DESTROY_FORCE | BE_DESTROY_ORIGIN | BE_DESTROY_AUTOORIGIN)

static int
l_destroy(lua_State *L)
{
	const char *name;
	int error, flags, nargs;

	L_REQUIRES_LIBBE(L);
	nargs = lua_gettop(L);
	luaL_argcheck(L, nargs >= 1, 1, "not enough arguments");
	name = luaL_checkstring(L, 1);
	flags = BE_DESTROY_AUTOORIGIN;
	if (nargs > 1) {
		flags = luaL_checkinteger(L, 2);
		luaL_argcheck(L, (flags & ~BE_DESTROY_FLAGS) == 0, 2,
		    "invalid flags set");
	}

	error = be_destroy(lbh, name, flags);
	L_ERRORRET_LIBBE(L, error);
	lua_pushboolean(L, 1);
	return (1);
}

#define	BE_MOUNT_FLAGS	(BE_MNT_FORCE | BE_MNT_DEEP)

static int
l_mount(lua_State *L)
{
	char mountpoint[BE_MAXPATHLEN];
	const char *name, *path;
	int error, flags, nargs;

	L_REQUIRES_LIBBE(L);
	nargs = lua_gettop(L);
	luaL_argcheck(L, nargs >= 1, 1, "not enough arguments");
	flags = 0;
	path = NULL;
	if (nargs >= 3) {
		flags = luaL_checkinteger(L, 3);
		luaL_argcheck(L, (flags & ~BE_MOUNT_FLAGS) == 0, 3,
		    "invalid flags set");
	}

	if (nargs >= 2)
		path = luaL_checkstring(L, 2);

	name = luaL_checkstring(L, 1);

	error = be_mount(lbh, name, path, flags, mountpoint);
	L_ERRORRET_LIBBE(L, error);
	lua_pushstring(L, mountpoint);
	return (1);
}

static const struct luaL_Reg l_be[] = {
	/** Switch to a different BE root.
	 * @param name	BE root (string)
	 * @return	true (boolean)
	 *		or nil, error (string) on error
	 */
	{"switch", l_switch},
	/** Get the name and path of the current root's active BE.
	 * @return	name (string), path (string)
	 *		or nil if libbe is not initialized
	 */
	{"active", l_active},
	/** Get the name and path of the current root's next active BE.
	 * @return	name (string), path (string)
	 *		or nil if libbe is not initialized
	 */
	{"nextboot", l_nextboot},
	/** Get the BE root libbe is currently operating on.
	 * @return	path (string)
	 *		or nil if libbe is not initialized
	 */
	{"root", l_root},
	/** Create a new boot environment.
	 * @param name		New environment name (string)
	 * @param origin	optional Origin snapshot or boot environment
	 * @return	true (boolean)
	 *		or nil, error (string) on error
	 */
	{"create", l_create},
	/** Create a snapshot of a boot environment.
	 * @param name		Boot environment to snapshot (string)
	 * @param snap		Name of the snapshot to create (string)
	 * @return	true (boolean)
	 *		or nil, error (string) on error
	 */
	{"snapshot", l_snapshot},
	/** Rename a boot environment.
	 * @param name		Boot environment's current name (string)
	 * @param newName	Boot environment's new name (string)
	 * @return	true (boolean)
	 *		or nil, error (string) on error
	 */
	{"rename", l_rename},
	/** Activate a boot environment.
	 * @param name		Boot environment to activate (string)
	 * @param temporary	optional Temporary/nextboot activate (boolean)
	 * @return	true (boolean)
	 *		or nil, error (string) on error
	 */
	{"activate", l_activate},
	/** Deactivate a boot environment.
	 * @param name		Boot environment to deactivate (string)
	 * @param temporary	optional Temporary/nextboot deactivate (boolean)
	 * @return	true (boolean)
	 *		or nil, error (string) on error
	 */
	{"deactivate", l_deactivate},
	/** Destroy a boot environment.
	 * @param name	Boot environment to destroy (string)
	 * @param flags	optional flags (integer)
	 * @return	true (boolean)
	 *		or nil, error (string) on error
	 */
	{"destroy", l_destroy},
	/** Mount a boot environment.
	 * @param name	Boot environment to mount (string)
	 * @param path	optional path to mount at (string)
	 * @param flags	optional mount flags (integer)
	 * @return	mountpath (string)
	 *		or nil, error (string) on error
	 */
	{"mount", l_mount},
	{"list", l_list},
	{NULL, NULL}
};

int
luaopen_be(lua_State *L)
{

	lua_newtable(L);

	luaL_setfuncs(L, l_be, 0);

	lbh = libbe_init(NULL);

	if (lbh != NULL)
		lua_pushstring(L, be_root_path(lbh));
	else
		lua_pushnil(L);
	lua_setfield(L, -2, "system_root");

	/* destroy_flags */
	lua_pushinteger(L, BE_DESTROY_FORCE);
	lua_setfield(L, -2, "DESTROY_FORCE");
	lua_pushinteger(L, BE_DESTROY_ORIGIN);
	lua_setfield(L, -2, "DESTROY_ORIGIN");
	lua_pushinteger(L, BE_DESTROY_AUTOORIGIN);
	lua_setfield(L, -2, "DESTROY_AUTOORIGIN");

	/* mount_flags */
	lua_pushinteger(L, BE_MNT_FORCE);
	lua_setfield(L, -2, "MNT_FORCE");
	lua_pushinteger(L, BE_MNT_DEEP);
	lua_setfield(L, -2, "MNT_DEEP");

	register_be_metatable(L);

	return (1);
}
