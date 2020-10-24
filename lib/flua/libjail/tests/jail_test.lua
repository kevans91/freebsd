--
-- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
--
-- Copyright (c) 2020 Kyle Evans <kevans@FreeBSD.org>
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--
-- $FreeBSD$
--

local atf = require("atf")
local jail = require("jail")

local jailname = "test_jail__"

-- Assume that we need root for creating jails, because we'd otherwise need a
-- MAC policy to grant it.
local JailCreatedTest = atf.TestCase "JailCreatedTest" {
	atf_auto = false,
	head = function()
		atf.set('require.user', 'root')
	end,
	cleanup = function()
		local jid = jail.getid(jailname)
		if jid then
			jail.remove(jid)
		end
	end,
}


local function helper_findme(jid)
	local njails, present = 0, false
	for jparam in jail.list() do
		njails = njails + 1
		if jparam["name"] == jailname then
			atf.check_equal(jid, tonumber(jparam["jid"]))
			present = true
		end
	end

	return njails, present
end

local function helper_check_attach(jail_ident)
	-- jail_ident will vary between jid and jail name
	local jid = jail.getid(jailname)

	local _, present = helper_findme(jid)
	atf.check_equal(true, present)

	jail.attach(jail_ident)
	_, present = helper_findme(jid)
	atf.check_equal(false, present)
end

local function helper_getparams(jail_ident)
	local jid = jail.getid(jailname)

	local jidret, params = jail.getparams(jail_ident,
	    {"jid", "name", "persist"})

	atf.check_equal(jid, jidret)
	local nparams = 0
	for k, v in pairs(params) do
		nparams = nparams + 1
		atf.check_equal(true, v ~= nil)
		atf.check_equal("string", type(v))
	end

	atf.check_equal(3, nparams)
	atf.check_equal("true", params["persist"])
end

atf.TestCase "allparams" {
	head = function()
		atf.set("descr",
		    "Test that jail.allparams() returns a table of strings")
	end,
	body = function()
		local allparams = jail.allparams()
		atf.check_equal(true, #allparams > 0)
		for k, v in ipairs(allparams) do
			atf.check_equal("string", type(v))
		end
	end,
}

JailCreatedTest "list" {
	body = function()
		atf.check_equal(nil, jail.getid(jailname))
		local jid, err = jail.setparams(jailname, {persist = "true"},
		    jail.CREATE)

		local njails, present = helper_findme(jid)

		atf.check_equal(true, present)
		atf.check_equal(true, njails >= 1)
	end
}

JailCreatedTest "create_unattached" {
	body = function()
		local jid, err = jail.setparams(jailname, {persist = "true"},
		    jail.CREATE)

		atf.check_equal(true, jid ~= nil)

		local _, present = helper_findme(jid)
		atf.check_equal(true, present)
	end,
}

JailCreatedTest "create_attached" {
	body = function()
		local jid, err = jail.setparams(jailname, {["children.max"]=1},
		    jail.CREATE | jail.ATTACH)

		atf.check_equal(true, jid ~= nil)

		local _, present = helper_findme(jid)
		-- If we're attached, we won't be able to find ourselves in a
		-- list.  This does assume that jail.list() works, but we have
		-- tests for that.
		atf.check_equal(false, present)
	end,
}

JailCreatedTest "attach_jid" {
	body = function()
		local jid, err = jail.setparams(jailname, {persist = "true"},
		    jail.CREATE)

		atf.check_equal(true, jid ~= nil)
		helper_check_attach(jid)
	end,
}

JailCreatedTest "attach_name" {
	body = function()
		local jid, err = jail.setparams(jailname, {persist = "true"},
		    jail.CREATE)

		atf.check_equal(true, jid ~= nil)
		helper_check_attach(jailname)
	end,
}

JailCreatedTest "getident" {
	body = function()
		local jid, err = jail.setparams(jailname, {persist = "true"},
		    jail.CREATE)

		atf.check_equal(true, jid ~= nil)
		atf.check_equal(jid, jail.getid(jailname))
		atf.check_equal(jailname, jail.getname(jid))
	end,
}

JailCreatedTest "getparams_jid" {
	body = function()
		local jid, err = jail.setparams(jailname, {persist = "true"},
		    jail.CREATE)

		atf.check_equal(true, jid ~= nil)
		helper_getparams(jid)
	end,
}

JailCreatedTest "getparams_name" {
	body = function()
		local jid, err = jail.setparams(jailname, {persist = "true"},
		    jail.CREATE)

		atf.check_equal(true, jid ~= nil)
		helper_getparams(jailname)
	end,
}

