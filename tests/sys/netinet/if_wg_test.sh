# $FreeBSD$
#
# SPDX-License-Identifier: BSD-2-Clause-FreeBSD
#
# Copyright (c) 2021 The FreeBSD Foundation
#
# This software was developed by Mark Johnston under sponsorship
# from the FreeBSD Foundation.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

. $(atf_get_srcdir)/../common/vnet.subr

atf_test_case "wg_basic" "cleanup"
wg_basic_head()
{
	atf_set descr 'Create a wg(4) tunnel over an epair and pass traffic between jails'
	atf_set require.user root
}

wg_basic_body()
{
	local epair pri1 pri2 pub1 pub2 wg1 wg2
        local endpoint1 endpoint2 tunnel1 tunnel2

	kldload -n if_wg

	pri1=$(openssl rand -base64 32)
	pri2=$(openssl rand -base64 32)

	endpoint1=192.168.2.1
	endpoint2=192.168.2.2
	tunnel1=169.254.0.1
	tunnel2=169.254.0.2

	epair=$(vnet_mkepair)

	vnet_init

	vnet_mkjail wgtest1 ${epair}a
	vnet_mkjail wgtest2 ${epair}b

	# Workaround for PR 254212.
	jexec wgtest1 ifconfig lo0 up
	jexec wgtest2 ifconfig lo0 up

	jexec wgtest1 ifconfig ${epair}a $endpoint1 up
	jexec wgtest2 ifconfig ${epair}b $endpoint2 up

	wg1=$(jexec wgtest1 ifconfig wg create listen-port 12345 private-key "$pri1")
	pub1=$(jexec wgtest1 ifconfig $wg1 | awk '/public-key:/ {print $2}')
	wg2=$(jexec wgtest2 ifconfig wg create listen-port 12345 private-key "$pri2")
	pub2=$(jexec wgtest2 ifconfig $wg2 | awk '/public-key:/ {print $2}')

	atf_check -s exit:0 -o ignore \
	    jexec wgtest1 ifconfig $wg1 peer public-key "$pub2" \
	    endpoint ${endpoint2}:12345 allowed-ips ${tunnel2}/32
	atf_check -s exit:0 \
	    jexec wgtest1 ifconfig $wg1 inet $tunnel1

	atf_check -s exit:0 -o ignore \
	    jexec wgtest2 ifconfig $wg2 peer public-key "$pub1" \
	    endpoint ${endpoint1}:12345 allowed-ips ${tunnel1}/32
	atf_check -s exit:0 \
	    jexec wgtest2 ifconfig $wg2 inet $tunnel2

	# Generous timeout since the handshake takes some time.
	atf_check -s exit:0 -o ignore jexec wgtest1 ping -c 3 -t 5 $tunnel2
	atf_check -s exit:0 -o ignore jexec wgtest2 ping -c 3 -t 5 $tunnel1
}

wg_basic_cleanup()
{
	vnet_cleanup
}

atf_init_test_cases()
{
	atf_add_test_case "wg_basic"
}
