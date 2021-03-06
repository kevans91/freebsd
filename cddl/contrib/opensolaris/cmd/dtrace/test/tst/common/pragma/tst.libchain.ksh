#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

libdir=${TMPDIR:-/tmp}/libdep.$$
dtrace=$1

setup_libs()
{
        mkdir $libdir
        cat > $libdir/liba.$$.d <<EOF
#pragma D depends_on library libb.$$.d

inline int foo = bar;
EOF
        cat > $libdir/libb.$$.d <<EOF
#pragma D depends_on module doogle_knows_all_probes

inline int bar = 0xd0061e;
EOF
}


setup_libs

$dtrace -L$libdir -e

status=$?
rm -rf $libdir
return $status
